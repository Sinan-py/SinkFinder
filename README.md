# SinkFinder

## Overview

The **SinkFinder** is a Python-based tool designed to scan websites for potentially vulnerable JavaScript code. It examines JavaScript files included in web pages and identifies if they contain any common sinks that could be exploited for Cross-Site Scripting (XSS) attacks or other vulnerabilities.

## Features

- Scans JavaScript files for known vulnerable sinks across various frameworks (e.g., React, Angular, Vue).
- Supports scanning inline scripts and external JavaScript files.
- Provides a progress update during the scan and outputs the total number of vulnerable sinks found.

## Requirements

- Python 3.x
- `requests` library
- `beautifulsoup4` library
- `esprima` library

You can install the required libraries using pip:

````bash
pip install requests beautifulsoup4 esprima

Usage
	1. Clone this repository:
		git clone https://github.com/Sinan-py/SinkFinder.git

	2. Navigate to the project directory:
		cd SinkFinder

	3. Run the scanner:
		python SinkFinder.py

	4. Enter the full URL of the website you want to scan when prompted.

License
This project is licensed under the MIT License - see the [LICENSE](https://github.com/Sinan-py/SinkFinder/blob/main/LICENSE) file for details.

Author
This project is maintained by Sinan Web3 (github.com/Sinan-py).

Contact
For any questions or issues, please contact backdoorkit@proton.me.


### LICENSE

```markdown
MIT License

Copyright (c) [2024] [Sinan_Web3]

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


## Important Notice

This software is licensed under the MIT License. While you are free to use, copy, and distribute this software, we request that you do not modify the code without prior permission. Unauthorized modifications to the code are not permitted and may violate the terms of the license. Please refer to the [LICENSE](https://github.com/Sinan-py/SinkFinder/blob/main/LICENSE) file for more details.

For any questions regarding the use and modification of this software, please contact [backdoorkit@proton.me].
````
