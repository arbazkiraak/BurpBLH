# BLH Plugin

Burp Extension to discover broken links using IScannerCheck & synchronized threads.

# Features

---

- Supports various HTML elements/attributes with regex based on following

[`https://github.com/stevenvachon/broken-link-checker/blob/09682b3250e1b2d01e4995bac77ec77cb612db46/test/helpers/json-generators/scrapeHtml.js`](https://github.com/stevenvachon/broken-link-checker/blob/09682b3250e1b2d01e4995bac77ec77cb612db46/test/helpers/json-generators/scrapeHtml.js)

- Concurrently checks multiple links using defined threads.
- Customizing **`[STATUS_CODES|PATH-PATTERN|MIME-TYPE]`**

[https://github.com/arbazkiraak/BurpBLH/blob/master/blhchecker.py#L20](https://github.com/arbazkiraak/BurpBLH/blob/master/blhchecker.py#L20)

# Usage

---

By default it passively scans the responses with Target "Scope in" . Make sure to add the targets into the scope. (Reason: To Avoid Noise)

`WHITELIST_CODES` - You can add status_code's to this list for more accurate results. 

ex: avoiding https redirects by adding `301`, if the path,url redirects to https.

`WHITELIST_PATTERN` - Regex extracting pattern based on given patterns.

- ex: /admin.php
- //google.com/test.jpg
- ../../img.src

`WHITELIST_MEMES` - Whitelisting MimeType to be processed for scanning patterns in responses if their Mime-Type matches.

ex: Mainly used to avoid performing regexes in `gif,img,jpg,swf etc`

`no_of_threads` - Increase no of threads , default : 15

---

# Output

- 2 Ways it outputs the broken links.
1. Broken Links which belongs to external origins.
2. Broken Links which belongs to same origins.
- If there are no external origin broken links then look for same origin broken links & return **same origin broken links.**
- if there are external origin broken links & same origin broken links then return only ***external origin broken links.***

OUTPUT1: External Origins

![](https://cdn-images-1.medium.com/max/1000/1*D6GdgfKlLvw8GYEuYQ5Exw.png)

OUTPUT2: Same Origins

![](https://cdn-images-1.medium.com/max/1000/1*4BAh1fjeVEw76swr_RyMgw.png)

This plugin is based on [https://github.com/stevenvachon/broken-link-checker](https://github.com/stevenvachon/broken-link-checker)
