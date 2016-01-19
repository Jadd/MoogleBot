# MoogleBot
A repository for a work-in-progess clientless FFXIV:ARR bot.

Whether or not the bot will have continued support is undecided at this point in time. Probably not. A few things to note about the code:

* FFXIV:ARR uses a block-cipher known as [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher)) to encrypt sensitive information, such as the login process.
* The aforementioned cipher has a modified implementation for unknown reasons, though it is suspected that it is due to unintentional optimizations done by the compiler. See usages of *CompatibilityMode* in the [Blowfish implementation](../master/MoogleBot.Runtime/Cryptography/Blowfish.cs).

Some other things to note:
* I am not liable for any damages caused with this code/software.
* The code in this repository is [licensed](../master/LICENSE).
* You can contact me [here](http://blog.ntoskr.nl/contact/) for any reason.