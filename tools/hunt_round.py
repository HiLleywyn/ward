"""Bounded public metadata collection. No executable bodies are requested."""
import argparse
import base64
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from ward.analyze import assess_repository
from ward.evidence import default_store, reviewed_repositories, snapshot_evidence
from ward.github import GitHubClient, GitHubError


def inspect(client, repo):
    name = repo['full_name']
    owner, project = name.split('/', 1)
    try:
        snapshot = client.snapshot(owner, project)
        result = assess_repository(snapshot)
        evidence = snapshot_evidence(snapshot)
        default_store().record_assessment(result, evidence)
        return {'repository':name, 'status':'UNKNOWN', 'assessment':result.to_dict(), 'evidence':evidence}
    except (GitHubError, ValueError) as error:
        payload = {'repository':name,'status':'UNKNOWN','error':str(error)}
        default_store().record(name, payload, kind='failed-scan')
        return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path('.local/hunts/2026-11-01.json'))
    args = parser.parse_args()
    client = GitHubClient()
    candidates = {}
    coverage = []
    for query in ('AnyPS5 in:name', 'KytyPS5 in:name', 'KyttyPS5 in:name'):
        repos = client.search_repositories(query, 100)
        coverage.append({'query':query,'returned':len(repos),'cap':100})
        for repo in repos:
            candidates[repo['full_name'].lower()] = repo
    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(inspect, client, repo) for repo in candidates.values()]
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            print(f"{len(results)}/{len(candidates)} {result['repository']} {result.get('assessment',{}).get('score','error')}", flush=True)
    availability = []
    for repo in reviewed_repositories():
        try:
            info = client._get(f"repos/{repo['repository']}")
            availability.append({'repository':repo['repository'],'availability':'public','id':info['id'],'created_at':info['created_at']})
        except GitHubError as error:
            availability.append({'repository':repo['repository'],'availability':'unavailable-or-inaccessible' if 'HTTP 404' in str(error) else 'unknown','error':str(error)[:200]})
    focused = []
    for name in ('anyps-5/AnyPS5-Github', 'KytyPS5-Emulator-For-PS5/.github'):
        info = client._get(f'repos/{name}')
        commits = client._get(f'repos/{name}/commits?per_page=100')
        head = commits[0]['sha']
        tree = client._get(f'repos/{name}/git/trees/{head}?recursive=1')
        source_files = [item for item in tree['tree'] if item['type']=='blob' and item['path'].endswith(('.cpp','.h','.c','.py','.js','.ps1','.sh'))]
        samples = []
        for item in source_files[:3]:
            if item.get('size',0) > 1000:
                continue
            blob = client._get(f"repos/{name}/git/blobs/{item['sha']}")
            content = base64.b64decode(blob['content']).decode('utf-8',errors='replace')
            samples.append({'path':item['path'],'git_blob':item['sha'],'text':content})
        focused.append({'repository':name,'repository_created_at':info['created_at'],'head':head,
            'earliest_returned_commit':commits[-1]['sha'],'earliest_returned_commit_date':commits[-1]['commit']['committer']['date'],
            'history_count':len(commits),'history_limit':100,'tree_truncated':tree.get('truncated'),
            'source_file_count':len(source_files),'source_bytes':sum(item.get('size',0) for item in source_files), 'samples':samples,
            'limit':'Dates and commits can be forged or imported. Earliest returned commit is not proof of campaign origin.'})
    payload = {'observed_at':datetime.now(timezone.utc).isoformat(),'coverage':coverage,
        'results':sorted(results,key=lambda x:x['repository'].lower()),'reviewed_availability':availability,'focused':focused}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(payload,indent=2),encoding='utf-8')
    print(f"Saved {len(results)} observations and {len(availability)} historical availability checks.")


if __name__ == '__main__':
    main()
