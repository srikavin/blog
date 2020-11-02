+++
title = "picoCTF 2018 - Lambdash"
date = 2018-10-18T14:08:16.365Z
updated = 2019-02-09T07:15:03.393Z
aliases = ["/posts/5bc893d0649fac2c4579918b-picoctf-2018-lambdash"]
[taxonomies]
tags = ['picoctf18', 'web']
categories = ["ctf-writeups"]
+++

# Problem
> C? Who uses that anymore. If we really want to be secure, we should all start learning lambda calculus. http://2018shell2.picoctf.com:41367

# Solution
An extremely large payload to the interpreter results in an `node.js` error message

```
PayloadTooLargeError: request entity too large
    at readStream (/problems/lambdash-3_0_867a993b23b277b2e144cc3e2d73f6e4/node_modules/raw-body/index.js:155:17)
    at getRawBody (/problems/lambdash-3_0_867a993b23b277b2e144cc3e2d73f6e4/node_modules/raw-body/index.js:108:12)
    at read (/problems/lambdash-3_0_867a993b23b277b2e144cc3e2d73f6e4/node_modules/body-parser/lib/read.js:77:3)
    at urlencodedParser (/problems/lambdash-3_0_867a993b23b277b2e144cc3e2d73f6e4/node_modules/body-parser/lib/types/urlencoded.js:116:5)
    at Layer.handle [as handle_request] (/problems/lambdash-3_0_867a993b23b277b2e144cc3e2d73f6e4/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/problems/lambdash-3_0_867a993b23b277b2e144cc3e2d73f6e4/node_modules/express/lib/router/index.js:317:13)
    at /problems/lambdash-3_0_867a993b23b277b2e144cc3e2d73f6e4/node_modules/express/lib/router/index.js:284:7
    at Function.process_params (/problems/lambdash-3_0_867a993b23b277b2e144cc3e2d73f6e4/node_modules/express/lib/router/index.js:335:12)
    at next (/problems/lambdash-3_0_867a993b23b277b2e144cc3e2d73f6e4/node_modules/express/lib/router/index.js:275:10)
    at expressInit (/problems/lambdash-3_0_867a993b23b277b2e144cc3e2d73f6e4/node_modules/express/lib/middleware/init.js:40:5)
```

<!-- more -->

We can access `/problems/lambdash-3_0_867a993b23b277b2e144cc3e2d73f6e4` through the shell server. After looking through 
the source code, we can see multiple `console.log` statements. I thought that these would likely be saved somewhere. After 
running `top` on the shell server, I found that there were multiple instances of lambdash running. After cding to the home 
directory, there is a hidden directory named `.forever`. Inside, there are multiple log files. Grepping these for `picoCTF` 
gives us the flag: `picoCTF{1_white_lie_and_your_proto_gets_pwnd_4679389f}`
