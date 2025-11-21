#!/usr/bin/env python3
"""Generate visualizations from packets CSV:

- Bar chart of top 10 destination ports (counts)
- Heatmap (table) of top source IP × dest port pairs

Usage: python3 visualize_ports.py --csv output/packets_YYYYmmdd_HHMMSS.csv --outdir output
If --csv is omitted the script picks the newest file matching output/packets_*.csv
"""
import argparse
import os
import glob
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Small port -> service map to annotate bars (keep in sync with sniffer)
PORT_SERVICE_MAP = {
    '53': 'DNS',
    '5353': 'mDNS',
    '67': 'DHCP-server',
    '68': 'DHCP-client',
    '1900': 'SSDP',
    '80': 'HTTP',
    '443': 'HTTPS',
    '22': 'SSH',
    '25': 'SMTP',
    '123': 'NTP',
    '161': 'SNMP',
    '445': 'SMB',
    '389': 'LDAP',
    '514': 'SYSLOG',
}


def find_latest_packets_csv(outdir):
    pattern = os.path.join(outdir, 'packets_*.csv')
    files = glob.glob(pattern)
    if not files:
        raise FileNotFoundError(f'No packets_*.csv found in {outdir}')
    return max(files, key=os.path.getmtime)


def annotate_port(p):
    if pd.isna(p) or p == '':
        return ''
    try:
        s = str(int(float(p))) if str(p).replace('.', '', 1).isdigit() else str(p)
    except Exception:
        s = str(p)
    svc = PORT_SERVICE_MAP.get(s)
    return f"{s} ({svc})" if svc else s


def bar_top_dst_ports(df, outpath, top_n=10):
    # coerce dst_port to string
    dst = df['dst_port'].astype(str).fillna('')
    counts = dst.value_counts()
    counts = counts[counts.index != '']
    top = counts.head(top_n)

    labels = [annotate_port(lbl) for lbl in top.index]

    plt.figure(figsize=(10, 6))
    sns.barplot(x=top.values, y=labels)
    plt.xlabel('Packet count')
    plt.ylabel('Destination port (service)')
    plt.title(f'Top {len(top)} destination ports')
    plt.tight_layout()
    plt.savefig(outpath)
    plt.close()


def heatmap_srcip_dstport(df, outpath_csv, outpath_png, top_src=20, top_dst=10):
    df2 = df.copy()
    df2['dst_port'] = df2['dst_port'].astype(str).fillna('')
    df2 = df2[df2['dst_port'] != '']

    top_dsts = df2['dst_port'].value_counts().head(top_dst).index.tolist()
    top_srcs = df2['src_ip'].value_counts().head(top_src).index.tolist()

    pivot = (
        df2[df2['dst_port'].isin(top_dsts) & df2['src_ip'].isin(top_srcs)]
        .groupby(['src_ip', 'dst_port'])
        .size()
        .unstack(fill_value=0)
    )

    pivot.to_csv(outpath_csv)

    if pivot.size == 0 or pivot.shape[0] == 0 or pivot.shape[1] == 0:
        plt.figure(figsize=(6, 3))
        plt.text(0.5, 0.5, 'No data available for heatmap', ha='center', va='center', fontsize=14)
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(outpath_png)
        plt.close()
        return

    plt.figure(figsize=(max(8, len(top_dsts)), max(6, len(top_srcs) / 2)))
    sns.heatmap(pivot, annot=True, fmt='d', cmap='YlGnBu')
    plt.ylabel('Source IP')
    plt.xlabel('Destination port')
    plt.title('Counts by source IP × destination port')
    plt.tight_layout()
    plt.savefig(outpath_png)
    plt.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--csv', help='Path to packets CSV (default: newest in --outdir)')
    p.add_argument('--outdir', default='output', help='Output folder for images (default: output)')
    p.add_argument('--top-src', type=int, default=20, help='Top N source IPs for heatmap (default 20)')
    p.add_argument('--top-dst', type=int, default=10, help='Top N dst ports for heatmap (default 10)')
    args = p.parse_args()

    if not os.path.isdir(args.outdir):
        os.makedirs(args.outdir, exist_ok=True)

    csvpath = args.csv or find_latest_packets_csv(args.outdir)
    print(f'Loading CSV: {csvpath}')
    df = pd.read_csv(csvpath)

    bar_out = os.path.join(args.outdir, 'top_dst_ports.png')
    heat_csv = os.path.join(args.outdir, 'srcip_dstport_counts.csv')
    heat_png = os.path.join(args.outdir, 'srcip_dstport_heatmap.png')

    bar_top_dst_ports(df, bar_out, top_n=10)
    print(f'Wrote bar chart: {bar_out}')

    heatmap_srcip_dstport(df, heat_csv, heat_png, top_src=args.top_src, top_dst=args.top_dst)
    print(f'Wrote heatmap CSV: {heat_csv}')
    print(f'Wrote heatmap image: {heat_png}')


if __name__ == '__main__':
    main()
