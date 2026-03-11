import re
import dns.resolver
import pandas as pd
from datetime import datetime, timedelta
import os

# --- 配置 ---
ADGUARD_RULE_FILE = 'adguard_rules.txt'  # 你的AdGuard规则文件路径
RECORD_FILE = 'domain_detection_records.csv' # 检测记录文件路径
PUBLIC_DNS_SERVERS = ['1.1.1.1', '8.8.8.8'] # 用于检测的公共DNS服务器

def check_domain_availability(domain):
    """
    通过DNS查询检测域名是否可用。
    如果能解析到A或AAAA记录，则认为可用。
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = PUBLIC_DNS_SERVERS
    # resolver.timeout = 2  # 设置查询超时时间
    # resolver.lifetime = 2 # 设置整个查询过程的超时时间

    try:
        # 尝试查询 A 记录
        resolver.query(domain, 'A')
        return True
    except dns.resolver.NXDOMAIN:
        # 域名不存在
        return False
    except dns.resolver.NoAnswer:
        # 域名存在但没有A记录（可能只有MX或NS记录），仍然认为是可解析的
        # 这里为了简化，我们认为没有A记录就不算“可用”，可以根据实际需求调整
        try:
             resolver.query(domain, 'AAAA') # 尝试查询AAAA记录
             return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.LifetimeTimeout):
             return False
    except (dns.resolver.Timeout):
        # 查询超时
        print(f"  Warning: DNS query timed out for {domain}, retrying...")
        try: # 尝试第二次
            resolver.query(domain, 'A')
            return True
        except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
    except Exception as e:
        # 其他错误
        # print(f"  Error checking {domain}: {e}")
        return False
    
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

    print(f'start _ {rule}')
    
    # 更严格的域名匹配模式，包括对端口号的可选匹配
    rule = rule.replace('@', '').replace('|', '').replace('^', '').replace('$', '')

    print(rule)
    pattern = r'^([a-zA-Z0-9*][a-zA-Z0-9*-]*\.)*[a-zA-Z0-9*][a-zA-Z0-9*-]*(\.a-zA-Z)?$'
    result = bool(re.match(pattern, rule))
    print(f'end _ {rule}')
    return result    
    

def process_denyallow_rule(rule):
    """
    处理单条 denyallow 规则
    逻辑：
    1. 严格检查：只允许 $denyallow=，不允许其他修饰符
    2. 安全校验：denyallow 后面的域名必须是主域名的子域
    """
    try:
        # --- 严格修饰符检查 ---
        if re.search(r'\$(?!denyallow=)', rule):
            return [] # 直接丢弃整条规则

        if '$denyallow=' not in rule:
            return []
            
        parts = rule.split('$denyallow=', 1)
        main_part = parts[0].strip()
        exception_part = parts[1].strip()

        # --- 提取主规则域名 ---
        main_domain = None
        if main_part.startswith('||') and main_part.endswith('^'):
            main_domain = main_part[2:-1]

        rules = []
        # 1. 保留主规则
        rules.append(main_part)

        # --- 处理例外列表 ---
        exception_parts = re.split(r'[|,^]+', exception_part)
        
        for part in exception_parts:
            domain = part.strip()
            if not domain:
                continue

            if main_part.startswith('@@'):
                # 原放行 -> 例外拦截 (生成黑名单/拦截规则)
                rules.append(f"||{domain}^")
            else:
                # 原拦截 -> 例外放行 (生成白名单/放行规则)
                rules.append(f"@@||{domain}^")
        
        return rules
        
    except Exception as e:
        # 捕获异常但不中断，返回空列表跳过该规则
        return []    

if __name__ == "__main__":
    
    # print(is_dns_rule('||0.beer^'))
    # print(is_dns_rule('||druggedrat.com^$all'))
    
    # print(is_dns_rule('||ad-host-backup-*.aliyuncs.com^'))

    print(is_dns_rule('@@|tan.601234.com^$important'))

    

    # print(process_denyallow_rule('||druggedrat.com^$denyallow=a.druggedrat.com|b.druggedrat.com'))

    