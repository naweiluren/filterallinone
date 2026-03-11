import requests
import argparse
import re

headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
    }

OFFICIAL_RULES = [
    "https://filters.adtidy.org/android/filters/2_optimized.txt",
    "https://filters.adtidy.org/android/filters/11_optimized.txt",
    "https://filters.adtidy.org/android/filters/17_optimized.txt",
    "https://filters.adtidy.org/android/filters/3_optimized.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext",
    "https://filters.adtidy.org/android/filters/4_optimized.txt",
    "https://filters.adtidy.org/android/filters/18_optimized.txt",
    "https://filters.adtidy.org/android/filters/19_optimized.txt",
    "https://filters.adtidy.org/android/filters/20_optimized.txt",
    "https://filters.adtidy.org/android/filters/21_optimized.txt",
    "https://filters.adtidy.org/android/filters/22_optimized.txt",
    "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",
    "https://secure.fanboy.co.nz/fanboy-annoyance_ubo.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/AnnoyancesList",
    "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt",
    "https://urlhaus-filter.pages.dev/urlhaus-filter-ag-online.txt",
    "https://filters.adtidy.org/android/filters/224_optimized.txt",
    "https://filters.adtidy.org/android/filters/15_optimized.txt",
    "https://filters.adtidy.org/android/filters/5_optimized.txt",
]

THIRD_PARTY_RULES = [
    "http://rssv.cn/adguard/api.php?type=black",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt", # 或者用代理：https://gh-proxy.com/raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt
    "https://raw.githubusercontent.com/lingeringsound/10007_auto/master/adb.txt",
    "https://www.kbsml.com/wp-content/uploads/adblock/adguard/adg-kall.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/Noyllopa/NoAppDownload/master/NoAppDownload.txt",
    "https://anti-ad.net/adguard.txt",
    "https://raw.githubusercontent.com/loveqqzj/AdGuard/master/Mobile.txt",
    #"https://raw.githubusercontent.com/qq5460168/dangchu/main/T%E7%99%BD%E5%90%8D%E5%8D%95.txt",
    "https://raw.githubusercontent.com/user001235/112/main/white.txt",
    #"https://file-git.trli.club/file-hosts/allow/Domains",
    #"https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
]

# THIRD_PARTY_RULES = [
#     "http://rssv.cn/adguard/api.php?type=black"
# ]

WHITE_LIST_RULES = [
    #"https://raw.githubusercontent.com/qq5460168/dangchu/main/T%E7%99%BD%E5%90%8D%E5%8D%95.txt",
    # "https://raw.githubusercontent.com/user001235/112/main/white.txt",
    # "https://file-git.trli.club/file-hosts/allow/Domains",
    # "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
]

def is_dns_rule(rule):
    """
    检查规则是否为只包含域名的 DNS 过滤规则。

    Args:
        rule: 要检查的规则字符串。

    Returns:
        如果规则是有效的 DNS 规则，则返回 True，否则返回 False。
    """
    if "/" in rule or "." not in rule:
        return False

    # print(f'start _ {rule}')
    
    # 更严格的域名匹配模式，包括对端口号的可选匹配
    rule = rule.replace('@', '').replace('|', '').replace('^', '').replace('$', '')

    # print(rule)
    pattern = r'^([a-zA-Z0-9*][a-zA-Z0-9*-]*\.)*[a-zA-Z0-9*][a-zA-Z0-9*-]*(\.a-zA-Z)?$'
    result = bool(re.match(pattern, rule))
    # print(f'end _ {rule}')
    return result   


proxies = {
    "http": "http://127.0.0.1:10808",
    "https": "http://127.0.0.1:10808", # Note: use 'http' scheme for the proxy URL in most cases
}


def download_rules(urls, dns_filename, general_filename):
    dns_rules = []
    general_rules = []

    for url in urls:
        print(f'{url}')
        try:
            # response = requests.get(url, proxies=proxies, headers=headers, timeout=5)
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            rules = response.text.splitlines()
            # print('1234')

            # rules = ['||heartlessanthemantiquity.com^$all']

            for rule in rules:

                # print(rule)
                if rule.startswith('!') or rule.startswith('#'):
                  continue

                if len(rule.strip()) <= 0:
                  continue
                
                rule = rule.replace('$important', '')
                if is_dns_rule(rule):
                    if not (rule.endswith('^') or rule.endswith('|')):
                        rule += '^'
                    if not (rule.startswith('@') or rule.startswith('|')):
                        rule = '||' + rule                  

                    if '$denyallow=' in rule:
                        parts = rule.split('$denyallow=', 1)
                        main_part = parts[0].strip()
                        exception_part = parts[1].strip()

                        # --- 提取主规则域名 ---
                        main_domain = None
                        if main_part.startswith('||') and main_part.endswith('^'):
                            main_domain = main_part[2:-1]

                        rules = []
                        # 1. 保留主规则
                        dns_rules.append(main_part)

                        # --- 处理例外列表 ---
                        exception_parts = re.split(r'[|,^]+', exception_part)
                        
                        for part in exception_parts:
                            domain = part.strip()
                            if not domain:
                                continue

                            if main_part.startswith('@@'):
                                # 原放行 -> 例外拦截 (生成黑名单/拦截规则)
                                dns_rules.append(f"||{domain}^")
                            else:
                                # 原拦截 -> 例外放行 (生成白名单/放行规则)
                                dns_rules.append(f"@@||{domain}^")
                    else:
                        dns_rules.append(rule)
                    #print(f"Identified general rule: {rule}")
                else:
                    # print(rule)
                    general_rules.append(rule)
                    #print(f"Identified DNS rule: {rule}")

        except requests.exceptions.RequestException as e:
            print(f"Error downloading {url}: {e}")

    with open(dns_filename, 'w', encoding='utf-8') as f:
        for rule in dns_rules:
            f.write(rule + '\n')

    with open(general_filename, 'w', encoding='utf-8') as f:
        for rule in general_rules:
            f.write(rule + '\n')

def download_whitelist_rules(urls, filename):
    whitelist_rules = []

    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            rules = response.text.splitlines()

            for rule in rules:
                if rule.startswith('!') or rule.startswith('#'):
                  continue

                if len(rule.strip()) <= 0:
                  continue

                if not rule.startswith('@'):
                  rule = '@@|' + rule

                if not rule.endswith('^'):
                    rule += '^'
                whitelist_rules.append(rule)
                
        except requests.exceptions.RequestException as e:
            print(f"Error downloading {url}: {e}")

    with open(filename, 'w', encoding='utf-8') as f:
        for rule in whitelist_rules:
            f.write(rule + '\n')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download AdGuard filter rules.")
    parser.add_argument('--type', choices=['official', 'third_party', 'whitelist'], required=True, help='Type of rules to download (official or third_party)')
    args = parser.parse_args()

    if args.type == 'official':
      download_rules(OFFICIAL_RULES, 'AdguardDNSRuler', 'AdguardRuler')
    elif args.type == 'third_party':
      download_rules(THIRD_PARTY_RULES, 'ziyongdnsZ', 'ziyongrulerZ')
    elif args.type == 'whitelist':
      download_whitelist_rules(WHITE_LIST_RULES, 'third_whitelist.txt')  