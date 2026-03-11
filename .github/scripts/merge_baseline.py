import os
import datetime
import pytz
import re


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

def merge_baseline(baseline_file="whitelist.txt"):
    dns_file="ziyongdnsZ"
    ziyong_file="ziyongrulerZ"
    dns_rules = []
    ziyong_rules = []

    try:
        with open(baseline_file, 'r', encoding='utf-8') as f:
            baseline_file = [line.strip() for line in f if line.strip()]  # 读取并去除空行

        for item in baseline_file:
            if is_dns_rule(item):
                dns_rules.append(item)
            else:
                ziyong_rules.append(item)     
    except FileNotFoundError:
        print(f"错误：找不到基准文件 {baseline_file}")
        return
    except Exception as e:
        print(f"读取基准文件时发生错误: {e}")
        return
    
    # print(dns_rules)
    # print(ziyong_rules)

    try:
        with open(dns_file, 'a', encoding='utf-8') as f:
            for rule in dns_rules:
                print(rule)
                f.write(rule + '\n')

        with open(ziyong_file, 'a', encoding='utf-8') as f:
            for rule in ziyong_rules:
                f.write(rule + '\n')        

        print(f"成功更新了 {dns_file} {ziyong_file} 文件")        
    except Exception as e:
        print(f"写入文件时发生错误: {e}")
        return

if __name__ == "__main__":
    merge_baseline(baseline_file="whitelist.txt")
    merge_baseline(baseline_file="blacklist.txt")
    # merge_whitelist(dns_file="ziyongdnsZ1", whitelist_file="third_whitelist.txt")