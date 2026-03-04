# Godzilla_AES_webshell-Channel-Stitch
基于哥斯拉底层反射的自定义AES通信插件，phpwebshell则基于Channel-Stitch生成

本项目主要是因为哥斯拉原生默认流量加密在过去几年被标记的太狠了。重新写了个AES的加密器，以及webshell的荷载生成。
## 本项目生成的荷载在Qwen2-0.5B-Instruct模型中经过30k webshell数据集训练微调后的小模型分析，并未命中，同时在长亭、阿里等webshell检测中也并未命中。

XOR在静态中太显眼而且会被解开分析，无缝对接PhpDynamicPayload。
无文件落地，零驻留内存解密执行，临时产生短暂随机缓存文件后瞬间自毁，规避长效静态监测。

<img width="2767" height="1376" alt="8e6f29ea85008ff0594cc713b558c421" src="https://github.com/user-attachments/assets/6cebe93a-166a-45f4-9ec3-f35738970f4c" />
<img width="2053" height="861" alt="073853c167d8787a0fc07e259043e71e" src="https://github.com/user-attachments/assets/bb3e3b52-3ca6-4811-8677-d138e38144ea" />
<img width="1273" height="965" alt="90958e5691087a8976449ebc70f860d0" src="https://github.com/user-attachments/assets/05b558d0-9a3a-400d-b5fc-fb579cc81604" />
