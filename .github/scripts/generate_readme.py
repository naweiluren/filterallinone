import os
import datetime
import pytz

def generate_readme(dns_file="ziyongdns", ruler_file="ziyongruler", readme_file="README.md"):
    """
    生成 README.md 文件，包含指定 DNS 和 Ruler 文件的行数。

    Args:
        dns_file: DNS 文件名 (默认为 "ziyongdnsZ")。
        ruler_file: Ruler 文件名 (默认为 "ziyongrulerZ")。
        readme_file: README 文件名 (默认为 "README.md")。
    """

    try:
        with open(dns_file, 'r') as f:
            dns_line_count = sum(1 for _ in f)
    except FileNotFoundError:
        dns_line_count = "File not found"

    try:
        with open(ruler_file, 'r', encoding='utf-8') as f:
            ruler_line_count = sum(1 for _ in f)
    except FileNotFoundError:
        ruler_line_count = "File not found"

    # 获取北京时间
    beijing_timezone = pytz.timezone('Asia/Shanghai')
    beijing_time = datetime.datetime.now(beijing_timezone).strftime("%Y-%m-%d %H:%M:%S")    

    readme_content = f"""
# filterallinone

```
    更新时间: {beijing_time} （北京时间） 

{dns_file}: {dns_line_count} lines
{ruler_file}: {ruler_line_count} lines
```

支持处理分解denyallow修饰词的dns规则
支持处理分解复杂非dns规则，进去去重
支持处理官方和自定义对不去重，去重自定义内官方规则
支持dns检测，每天检测新增加dns规则，无效则每七天一次，持续四次，无效删除，半年重检一次
    """

    with open(readme_file, 'w', encoding='utf-8') as f:
        f.write(readme_content)

    print(f"README file '{readme_file}' generated successfully.")

if __name__ == "__main__":
    generate_readme()