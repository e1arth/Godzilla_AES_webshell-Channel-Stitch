<h1 align="center">VeilShell</h1>

### Godzilla_AES加密器+采用custom stream wrapper的webshell|Qwen2-0.5B-Instruc-webshell微调小模型检测方法与对抗。
插件是基于哥斯拉底层反射的自定义AES通信加密器，phpwebshell则基于AES + gzdeflate+custom stream wrapper。

本项目
## 本项目生成的荷载在Qwen2-0.5B-Instruct模型中经过30k webshell数据集训练微调后的小模型分析，并未命中。同时在长亭、阿里等产品的webshell检测中也完美绕过。

对于结果有疑虑可阅读：[Qwen2-0.5B-Instruc-webshell微调模型检测训练](./微调模型训练/README.md) 

注：该图展示的样本是二次过滤后的恶意样本，选了40+能过waf的phpwebshell进行测试。并不代表全量训练数据集，全量数据集采用了https://huggingface.co/datasets/nbuser32/PHP-Webshell-Dataset

<img width="1640" height="729" alt="b02a5230965decbd5961bc86453f3b47" src="https://github.com/user-attachments/assets/90c0cec6-ab67-411e-923d-fe0ee1ee34a7" />
<img width="1640" height="793" alt="image" src="https://github.com/user-attachments/assets/90fab391-3481-4850-a29b-f393825f52ac" />

> Test metrics: {'test_loss': 0.08689013123512268, 'test_accuracy': 0.973571192599934, 'test_f1': 0.9750623441396509, 'test_precision': 0.993015873015873, 'test_recall': 0.9577464788732394, 'test_runtime': 71.2095, 'test_samples_per_second': 42.508, 'test_steps_per_second': 2.668, 'epoch': 1.0}
---- 
---- 
长亭：
<img width="2767" height="1376" alt="8e6f29ea85008ff0594cc713b558c421" src="https://github.com/user-attachments/assets/6cebe93a-166a-45f4-9ec3-f35738970f4c" />

阿里：
<img width="2053" height="861" alt="073853c167d8787a0fc07e259043e71e" src="https://github.com/user-attachments/assets/bb3e3b52-3ca6-4811-8677-d138e38144ea" />

正常连接及环境：
<img width="2880" height="1358" alt="image" src="https://github.com/user-attachments/assets/0e3ce29a-b0c5-46c6-9f57-fed92b2932aa" />

post：
<img width="1273" height="965" alt="90958e5691087a8976449ebc70f860d0" src="https://github.com/user-attachments/assets/05b558d0-9a3a-400d-b5fc-fb579cc81604" />
