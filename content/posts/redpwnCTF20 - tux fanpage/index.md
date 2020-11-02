+++
title = "redpwnCTF - tux fanpage"
date = 2020-06-25
aliases = ["/posts/5ef4cb041d3e7302fc8a3416-redpwnctf-tux-fanpage"]
[taxonomies]
tags = ["redpwnctf20", "web", "local-file-inclusion"]
categories = ["ctf-writeups"]
+++

# Challenge

> My friend made a fanpage for Tux; can you steal the source code for me?
>
> Site: [tux-fanpage.2020.redpwnc.tf](http://tux-fanpage.2020.redpwnc.tf)

We're also given the source code:

<!-- more -->

{{ gist(url="https://gist.github.com/srikavin/88989ab1c98ab52f94c86593e3d30b5a") }}


# Local File Inclusion

When we open the site we're greeted by a wonderfully-designed site. The URL also includes a path parameter: `https://tux-fanpage.2020.redpwnc.tf/page?path=index.html`. Looking at the source code shows us that the path is used to load a file from the file system after a series of checks:

```javascript
//Prevent directory traversal attack
function preventTraversal(dir){
    if(dir.includes('../')){
        let res = dir.replace('../', '')
        return preventTraversal(res)
    }

    //In case people want to test locally on windows
    if(dir.includes('..\\')){
        let res = dir.replace('..\\', '')
        return preventTraversal(res)
    }
    return dir
}

//Get absolute path from relative path
function prepare(dir){
    return path.resolve('./public/' + dir)
}

//Strip leading characters
function strip(dir){
    const regex = /^[a-z0-9]$/im

    //Remove first character if not alphanumeric
    if(!regex.test(dir[0])){
        if(dir.length > 0){
            return strip(dir.slice(1))
        }
        return ''
    }

    return dir
}
```


There's no clear way to bypass these checks. 

## Express.js Query Parsing

Express, [by default](https://expressjs.com/en/api.html#app.settings.table), uses the npm package [`qs`](https://www.npmjs.com/package/qs) to decode query parameters. 

qs can parse certain query parameters into strings and objects. However, the parameters we choose need to pass the validation. Using an object fails when reaching `preventTraversal` because `includes` is not a function on objects. Using an array works, but `../` is still removed from the array in `preventTraversal`

### Nested Arrays

Using a nested array bypasses the 'includes` check because a string cannot equal an array (even in Javascript). This leads to the final solution:
`https://tux-fanpage.2020.redpwnc.tf/page?path[0]=a&path[1][1]=../../../index.js`, and we find the flag:

`flag{tr4v3rsal_Tim3}`
