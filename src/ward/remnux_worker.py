"""Fixed worker program passed to REMnux's Python; never imports sample code."""
from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import json
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile


MAX_BYTES = 32 * 1024 * 1024
MAX_OUTPUT = 8 * 1024 * 1024


def run_tool(name, command, timeout):
    if shutil.which(command[0]) is None:
        return {"name": name, "status": "unavailable"}
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        try:
            run = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                 stderr=errors, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"name": name, "status": "timeout"}
        size = output.tell()
        output.seek(0)
        text = output.read(MAX_OUTPUT).decode("utf-8", errors="replace")
        error_size = errors.tell()
        errors.seek(max(0, error_size - 2000))
        warnings = errors.read(2000).decode("utf-8", errors="replace").strip()
    if size >= MAX_OUTPUT or error_size >= MAX_OUTPUT:
        return {"name": name, "status": "partial", "detail": "Tool output reached its byte limit"}
    if run.returncode:
        return {"name": name, "status": "failed", "exit_code": run.returncode,
                "detail": (warnings or text or f"Tool exited with code {run.returncode}")[-2000:]}
    result = {"name": name, "status": "completed", "output": text}
    if warnings:
        result["warnings"] = warnings
    return result


def analyze(data):
    engines = []
    path = Path("/samples/sample.bin")
    path.write_bytes(data)
    identified = run_tool("file", ["file", "--brief", str(path)], 10)
    engines.append(identified)
    is_pe = data.startswith(b"MZ")
    packed = is_pe and b"MEI\x0c\x0b\x0a\x0b\x0e" in data
    if is_pe:
        try:
            import pefile
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            imports = []
            truncated = len(pe.sections) > 96 or len(getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])) > 128
            for library in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:128]:
                truncated |= len(library.imports) > 256
                imports.append({
                    "library": library.dll.decode("utf-8", errors="replace"),
                    "symbols": [(symbol.name or str(symbol.ordinal).encode()).decode("utf-8", errors="replace")
                                for symbol in library.imports[:256]],
                })
            engines.append({"name": "pefile", "status": "partial" if truncated else "completed", "version": importlib.metadata.version("pefile"),
                            "machine": pe.FILE_HEADER.Machine, "timestamp": pe.FILE_HEADER.TimeDateStamp,
                            "entrypoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                            "sections": [{"name": section.Name.rstrip(b"\0").decode("utf-8", errors="replace"),
                                          "size": section.SizeOfRawData, "entropy": round(section.get_entropy(), 3)}
                                         for section in pe.sections[:96]], "imports": imports})
            pe.close()
        except ImportError:
            engines.append({"name": "pefile", "status": "unavailable"})
        except Exception as exc:
            engines.append({"name": "pefile", "status": "failed", "detail": str(exc)[:500]})
        identified_packer = run_tool("detect-it-easy", ["diec", "--json", str(path)], 30)
        if identified_packer["status"] == "completed":
            try:
                identified_packer["result"] = json.loads(identified_packer.pop("output"))
            except ValueError:
                identified_packer = {"name": "detect-it-easy", "status": "failed", "detail": "Invalid tool JSON"}
        engines.append(identified_packer)
        if packed:
            capabilities = {"name": "capa", "status": "not-run", "scope": "packed-content-unresolved",
                            "limitation": "PyInstaller archive marker detected. Native launcher capabilities cannot establish bundled Python or encrypted payload behavior; unpacking is required."}
        else:
            capabilities = run_tool("capa", ["capa", "--json", "--quiet", str(path)], 60)
            capabilities["scope"] = "static-capabilities"
        if capabilities["status"] == "completed":
            try:
                document = json.loads(capabilities.pop("output"))
                capabilities["version"] = document.get("meta", {}).get("version")
                if len(document.get("rules", {})) > 200:
                    capabilities["status"] = "partial"
                capabilities["capabilities"] = [
                    {"name": name, "namespace": rule.get("meta", {}).get("namespace"),
                     "att&ck": rule.get("meta", {}).get("att&ck", []),
                     "match_count": len(rule.get("matches", []))}
                    for name, rule in list(document.get("rules", {}).items())[:200]
                ]
            except (TypeError, ValueError) as exc:
                capabilities = {"name": "capa", "status": "failed", "detail": "Invalid tool JSON: " + str(exc)[:200]}
        engines.append(capabilities)
    else:
        engines.extend({"name": name, "status": "not-applicable"} for name in ("pefile", "capa"))
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "engines": engines,
            "coverage": "partial" if packed or any(engine["status"] not in {"completed", "not-applicable"} for engine in engines) else "completed",
            "behavioral_analysis": "not-run"}


def main():
    def expired(signum, frame):
        raise TimeoutError("REMnux guest deadline exceeded")

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(110)
    # capa unpacks its trusted runtime libraries into scratch before analysis.
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024 * 1024, 128 * 1024 * 1024))
    raw = sys.stdin.buffer.read(45 * 1024 * 1024 + 1)
    if len(raw) > 45 * 1024 * 1024:
        raise ValueError("Input exceeds the worker limit")
    request = json.loads(raw)
    data = base64.b64decode(request["content_base64"], validate=True)
    if not data or len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != request["sha256"]:
        raise ValueError("Sample size or digest is invalid")
    print(json.dumps(analyze(data)))


if __name__ == "__main__":
    main()
