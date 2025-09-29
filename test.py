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
    

if __name__ == "__main__":
    
    print(check_domain_availability('www.naweiluren.com'))