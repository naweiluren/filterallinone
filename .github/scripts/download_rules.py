import requests
import argparse
import re
import json
import os
from datetime import datetime
from collections import deque

# 添加日志文件配置
LOG_FILE = "download_log.json"
MAX_LOG_PER_URL = 3  # 保留最近3次记录

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


def load_download_log():
    """加载下载日志"""
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_download_log(log_data):
    """保存下载日志，为每个URL只保留最近MAX_LOG_PER_URL条记录"""
    # 为每个URL只保留最近MAX_LOG_PER_URL条记录
    for url in log_data:
        if len(log_data[url]) > MAX_LOG_PER_URL:
            log_data[url] = log_data[url][-MAX_LOG_PER_URL:]
    
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(log_data, f, ensure_ascii=False, indent=2)

def update_download_log(url, status, error_msg=None):
    """更新指定URL的下载状态"""
    log_data = load_download_log()
    
    # 确保log_data是字典
    if not isinstance(log_data, dict):
        log_data = {}
    
    # 如果URL不存在，创建新的列表
    if url not in log_data:
        log_data[url] = []
    
    # 创建新的日志条目
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_entry = {
        "timestamp": current_time,
        "status": status,
        "error": error_msg if error_msg else ""
    }
    
    log_data[url].append(new_entry)
    save_download_log(log_data)

def download_rules(urls, dns_filename, general_filename):
    dns_rules = []
    general_rules = []
    
    for url in urls:
        print(f'正在下载: {url}')
        
        try:
            # response = requests.get(url, proxies=proxies, headers=headers, timeout=5)
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            rules = response.text.splitlines()
            
            # 记录成功
            update_download_log(url, "success")
            print(f'✅ 下载成功: {url}')
            
            for rule in rules:
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
                else:
                    general_rules.append(rule)

        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            print(f'❌ 下载失败: {url} - {error_msg}')
            # 记录失败
            update_download_log(url, "failed", error_msg)

    # 写入规则文件
    with open(dns_filename, 'w', encoding='utf-8') as f:
        for rule in dns_rules:
            f.write(rule + '\n')

    with open(general_filename, 'w', encoding='utf-8') as f:
        for rule in general_rules:
            f.write(rule + '\n')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download AdGuard filter rules.")
    parser.add_argument('--type', choices=['official', 'third_party', 'whitelist'], required=True, help='Type of rules to download (official or third_party)')
    args = parser.parse_args()

    if args.type == 'official':
      download_rules(OFFICIAL_RULES, 'AdguardDNSRuler', 'AdguardRuler')
    elif args.type == 'third_party':
      download_rules(THIRD_PARTY_RULES, 'ziyongdnsZ', 'ziyongrulerZ')