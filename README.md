# SmCrypto

本项目是对[`sm-crypto`](https://github.com/JuneAndGreen/sm-crypto)（`JavaScript`实现）算法的其他语言实现，主要目的是同步其加密和解密接口。

计划中的实现语言，以及其目前各自的实现情况如下：

| 语言     | SM2算法                      | SM3算法      | SM4算法      |
| -------- | ---------------------------- | ------------ | ------------ |
| `Rust`   | $\checkmark$（仅供学习使用） | $\checkmark$ | $\checkmark$ |
| `Python` | $-$                          | $\checkmark$ | $\checkmark$ |
| `Go`     | $-$                          | $-$          | $-$          |
| `Nim`    | $-$                          | $-$          | $\checkmark$ |

> `SM2`算法的实现均仅供学习使用。

## 安全声明

`SM2`算法的实现均仅供**学习**使用。

### Rust实现

`Rust`实现使用了`num-bigint`库并非为了密码学设计，其

   - 没有常数时间保证，易受*定时攻击*；
   - 内部可能存在内存分配模式可观察性，易受*侧信道攻击*；
   - 不提供随机化缓解措施，易受*故障注入攻击*；
   - 缺少密码学必要的安全性检查，未实现标准化的随机数生成（目前使用`rand`库而非符合密码学标准的`RNG`）。 

如果需要在生产中使用`SM2`，建议选择如下实现：

- ……

> [`sm2`](https://docs.rs/sm2/)实现了`SM2`的常数级别的椭圆曲线运算，但没有实现加解密、签名和验签。

## 使用示例

对于各语言的模块调用示例，请参考各语言的文件夹中的`tests`测试示例。

## 其他

- 原项目地址：[`sm-crypto`](https://github.com/JuneAndGreen/sm-crypto)
- 原作者主页：[`JuneAndGreen`](https://github.com/JuneAndGreen)
