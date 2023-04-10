import falconpy
from tabulate import tabulate
from termcolor import colored
import argparse
import json

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='A simple utility to dump detected behaviors from a CrowdStrike console.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--client-id', help='Client ID to use in the API.')
    parser.add_argument('--secret', help='Secret to use in the API.')
    parser.add_argument('--filter', help='Filter to use for detections.', default='')
    parser.add_argument('--limit', help='Limit to use for query.', default=100)
    parser.add_argument('--offset', help='Offset to use for query.', default=0)
    parser.add_argument('--sort', help='Criteria to use for sorting results.', default='first_behavior|desc')
    parser.add_argument('--json', help='Dump detection objects as JSON instead of showing table.', action='store_true')
    parser.add_argument('--detections-only', help='Show detections only - not their individual behaviors.', action='store_true')

    args = parser.parse_args()

    client_id = args.client_id
    client_secret = args.secret

    detects = falconpy.Detects(
        client_id=client_id,
        client_secret=client_secret
    )

    offset = args.offset
    limit = args.limit
    sort = args.sort
    _filter = args.filter

    detection_ids = detects.query_detects(
        filter=_filter, 
        limit=limit,
        sort=sort,
        offset=offset
    ).get('body', {}).get('resources', [])

    summaries = detects.get_detect_summaries(
        ids=detection_ids
    )
    detections = summaries.get('body', {}).get('resources', [])

    headers = ["Start", "Host", "Status", "Tactic", "Technique", "Behavior", "Filename", "Severity"]

    status_colors = {
        "false_positive": "yellow",
        "ignored": "magenta",
        "new": "blue",
        "true_positive": "green",
        "in_progress": "cyan"
    }

    if args.json:
        print(json.dumps(detections))
        exit(0)

    def aggregate(x, fn):
        n = len(set(x))
        if n == 1:
            return fn(x[0])
        else:
            return f'Multiple ({n})'

    data = []
    for detection in detections:
        detection_id = detection.get("detection_id", "")
        host_info = detection.get("device", {}).get("hostname", "")
        status = detection.get("status", "")
        status_colored = colored(status, status_colors[status])
        description = detection.get("description", "")
        severity = detection.get("max_severity", "")
        if severity >= 80:
            severity_color = "red"
        elif severity >= 60:
            severity_color = "light_red" 
        elif severity >= 40:
            severity_color = "yellow"
        else:
            severity_color = "white"
        severity_colored = colored(severity, severity_color)
        first_behavior = detection.get("first_behavior", "")
        last_behavior = detection.get("last_behavior", "")
        behaviors_obj = detection.get("behaviors", "")

        if not args.detections_only:
            for behavior in behaviors_obj:
                filename = behavior.get('filename', '')
                tactic = behavior.get('tactic', '')
                technique = behavior.get('technique', '')
                behavior_name = behavior.get('display_name', '')
                behavior_id = behavior.get('behavior_id', 0)
                if behavior_name != '':
                    behavior_info = f'{behavior_id} ({behavior_name})'
                else:
                    behavior_info = str(behavior_id)

                data.append([
                    first_behavior,
                    host_info,
                    status_colored,
                    tactic,
                    technique,
                    behavior_info,
                    filename,
                    severity_colored
                ])
        else:
            n_filenames = len(set(behavior.get('filename', '') for behavior in behaviors_obj))
            n_tactics = len(set(behavior.get('tactic', '') for behavior in behaviors_obj))
            n_techniques = len(set(behavior.get('technique', '') for behavior in behaviors_obj))
            n_behaviors = len(behaviors_obj)

            if len(behaviors_obj) == 1:
                behavior = behaviors_obj[0]
                filename = behavior.get('filename', '')
                tactic = behavior.get('tactic', '')
                technique = behavior.get('technique', '')
                behavior_name = behavior.get('display_name', '')
                behavior_id = behavior.get('behavior_id', 0)
                if behavior_name != '':
                    behavior_info = f'{behavior_id} ({behavior_name})'
                else:
                    behavior_info = str(behavior_id)
            else:
                behavior_info = f'Multiple ({n_behaviors})'

                filename = aggregate(
                    [behavior.get('filename', '') for behavior in behaviors_obj],
                    str
                )

                tactic = aggregate(
                    [behavior.get('tactic', '') for behavior in behaviors_obj],
                    str
                )

                technique = aggregate(
                    [behavior.get('technique', '') for behavior in behaviors_obj],
                    str
                )

            data.append([
                first_behavior,
                host_info,
                status_colored,
                tactic,
                technique,
                behavior_info,
                filename,
                severity_colored
            ])

    table = tabulate(
        data,
        headers=headers,
        colalign=("center", "left", "center", "left", "center", "left"),
        numalign="center"
    )

    print(table)