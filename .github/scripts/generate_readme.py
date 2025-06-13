import os
import datetime
import pyt

def generate_readme(dns_file="ziyongdnsZ", ruler_file="ziyongrulerZ", readme_file="README.md"):
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
        with open(ruler_file, 'r') as f:
            ruler_line_count = sum(1 for _ in f)
    except FileNotFoundError:
        ruler_line_count = "File not found"

    # 获取北京时间
    beijing_timezone = pytz.timezone('Asia/Shanghai')
    beijing_time = datetime.datetime.now(beijing_timezone).strftime("%Y-%m-%d %H:%M:%S")    

    readme_content = f"""
    更新时间: {beijing_time} （北京时间） 

*   **{dns_file}:** {dns_line_count} lines
*   **{ruler_file}:** {ruler_line_count} lines

    """

    with open(readme_file, 'w') as f:
        f.write(readme_content)

    print(f"README file '{readme_file}' generated successfully.")

if __name__ == "__main__":
    generate_readme()