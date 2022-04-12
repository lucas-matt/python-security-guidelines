## Python Security Guidelines

<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/c/c3/Python-logo-notext.svg/640px-Python-logo-notext.svg.png" alt="drawing" width="150"/>

>>>

## OWASP Vulnerabilities 2021


1. <span style="color:#FFFFA7">Broken Access Control</span>
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery


>>>

<span style="color:#FFFFA7">**Broken Access Control**</span>

<p class="fragment">
Access control enforces policy to prevent users from acting outside of their intended permissions.
</p>


>>>

#### 1.1 Insecure temporary file creation

<p class="fragment">
Creating temporary files using insecure methods exposes the application to race conditions on filenames.
</p>



vvv

A malicious user can try to create a file with a predictable name before the application does. 

<pre>
<code data-line-numbers="">
import tempfile

filename = tempfile.mktemp() # Noncompliant
tmp_file = open(filename, "w+") # Open as second step
</code>
</pre>

<div class="fragment">

Use more secure (atomic) methods of temporary file creation

<pre>
<code data-line-numbers="0-100|4">
# create filename and open
# deleted automatically
with NamedTemporaryFile(mode="w+", delete=True) as tmp_file:
  tmp_file.write(results)
</code>
</pre>

</div>


>>>

#### 1.2 Allowing both safe and unsafe HTTP methods

<p class="fragment">
A HTTP method is <b style="color:green">safe</b> when used to perform a read-only operation (e.g. GET or HEAD)
</p>

<p class="fragment">
An <b style="color:red">unsafe</b> HTTP method is used to change the state of an application (e.g. POST or PUT)
</p>

vvv

<b style="color:red">Unsafe</b> HTTP methods are generally more protected.

Ensure you're not using <b style="color:green">safe</b> HTTP methods to perform insecure operations (e.g. a GET to change state).

vvv

<div >
Unsafe

<pre>
<code data-line-numbers="0-10|2">
@require_http_methods(["GET", "POST"])  # Sensitive
def view(request):
    return HttpResponse("...")
</code>
</pre>

</div>


<div class="fragment">

Safe

<pre>
<code data-line-numbers="0-10|2">
@require_http_methods(["POST"])
def view(request):
    return HttpResponse("...")
</code>
</pre>

</div>

>>>

#### 1.3 Using publicly writable directories is security-sensitive

Folders, such as </code>
</pre>/tmp</code>
</pre> and </code>
</pre>/var</code>
</pre> are writable by all users on the system.

Be careful using these folders, and avoid if possible.

vvv

Don't use publicly writable directories

<pre>
<code data-line-numbers="">
file = open("/tmp/temporary_file","w+") # Sensitive
</code>
</pre>

<div class="fragment">

Use a dedicated folder with tightly controlled permissions.

<pre>
<code data-line-numbers="">
import tempfile

file = tempfile.TemporaryFile(dir="/tmp/my_subdirectory", mode='"w+") # Compliant
</code>
</pre>

</div>


>>>

#### 1.4 Setting loose POSIX file permissions is security-sensitive

The **most restrictive possible** permissions should be assigned to files and directories to avoid unintended access by other users.

<p class="fragment">
<span style="color:red">chmod 777</span> is evil
</p>

>>>

#### 1.5 I/O function calls should not be vulnerable to path injection attacks

<p class="fragment">
User-provided data should always be considered untrusted and tainted. 
</p>

<p class="fragment" style="color:yellow">
Constructing file system paths directly from user data could enable an attacker to inject specially crafted values, such as '../'
</p>

vvv

Unsafe

<pre>
<code data-line-numbers="0-10|5,6">
@app.route('/download')
def download():
    file = request.args['file']
    # could use "../" to escape the intended directory
    return send_file("static/%s" % file, as_attachment=True) # Noncompliant
</code>
</pre>

<div class="fragment">

Safe

<pre>
<code data-line-numbers="0-10|5,6">
@app.route('/download')
def download():
    file = request.args['file']
    # fixed to specific directory
    return send_from_directory('static', file) # Compliant
</code>
</pre>

</div>

>>>

#### 1.6 HTTP request redirections should not be open to forging attacks

<p class="fragment">
User-provided data should always be considered untrusted and tainted. 
</p>

<p class="fragment" style="color:yellow">
Applications performing HTTP redirects based on tainted data could enable an attacker to redirect users to a malicious site.
<p>

vvv

Unsafe

<pre>
<code data-line-numbers="|5">
@app.route('flask_redirect')
def flask_redirect():
    url = request.args["next"]
    return redirect(url)  # Noncompliant
</code>
</pre>

<div class="fragment">

Instead, validate user-provided data, or redesign the application to avoid redirects.

<pre>
<code data-line-numbers="|5">
@app.route('flask_redirect')
def flask_redirect():
    endpoint = request.args["next"]
    return redirect(url_for(endpoint))  # Compliant
</code>
</pre>

</div>

<div class="fragment">

</code>
</pre>url_for</code>
</pre> redirects within the app, and not to an external site.

</div>

>>>

#### 1.7 Expanding archive files in an uncontrolled way

<p class="fragment">
A Zip bomb is usually a malicious archive file of a few kilobytes of compressed data that turns into gigabytes of uncompressed data.
</p>

<div class="fragment">

<pre>
<code data-line-numbers="|5">
import zipfile

zfile = zipfile.ZipFile('ZipBomb.zip', 'r')
zfile.extractall('./tmp/') # Sensitive
zfile.close()
</code>
</pre>

</div>

vvv

To protect against Zip bombs:

* Limit the ratio of compressed vs expanded size
* Limit the maximum expanded size
* Limit the number of file entries extracted

>>>

#### 1.8 Using hardcoded IP addresses is security-sensitive

Disclosing IP addresses within an application can ...

<div class="fragment">
1. Leak information about network topology.
</div>

<div class="fragment">
2. Leak personal details.
</div>

vvv

Avoid hard-coding details

<pre>
<code data-line-numbers="|2">
ip = '192.168.12.42'
sock = socket.socket()
sock.bind((ip, 9090))
</code>
</pre>

<div class="fragment">

Instead, use configuration or environment variables

<pre>
<code data-line-numbers="|2">
ip = config.get(section, ipAddress)
sock = socket.socket()
sock.bind((ip, 9090))
</code>
</pre>

</div>

>>>

## OWASP Vulnerabilities 2021

1. Broken Access Control
2. <span style="color:#FFFFA7">Cryptographic Failures</span>
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery


>>>

<span style="color:#FFFFA7">**Cryptographic Failures**</span>

<p class="fragment">
Failures related to cryptography often lead to sensitive data exposure or system compromise.
</p>


>>>

#### 2.1 Weak SSL/TLS protocols should not be used

<p class="fragment">
Older versions of SSL/TLS protocol such as "SSLv3" have been proven to be insecure.
</p>

vvv

Avoid insecure protocols

<pre>
<code data-line-numbers="|4">
from OpenSSL import SSL

SSL.Context(SSL.SSLv3_METHOD)  # Noncompliant
</code>
</pre>

<div class="fragment">

Protocol versions different from TLSv1.2 and TLSv1.3 are considered insecure.

<pre>
<code data-line-numbers="|4">
from OpenSSL import SSL

SSL.Context(SSL.TLSv1_2_METHOD)  # Compliant
</code>
</pre>

</div>


>>>

#### 2.2 Server hostnames should be verified during SSL/TLS connections

<p class="fragment">
To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate.
</p>

<p class="fragment" style="color:green">
The certificate's hostname-specific data should match the server hostname.
</p>

vvv

Don't re-invent the wheel by implementing custom hostname verification.

<pre>
<code data-line-numbers="|3">
ctx = ssl.create_default_context()
ctx.check_hostname = False # Noncompliant
</code>
</pre>

<div class="fragment">

TLS/SSL libraries provide built-in hostname verification functions that should be used.

<pre>
<code data-line-numbers="|3">
ctx = ssl._create_stdlib_context()
ctx.check_hostname = True # Compliant
</code>
</pre>

</div>

>>>

#### 2.3 Server certificates should be verified during SSL/TLS connections

<p class="fragment">
Validation of X.509 certificates is essential to create secure SSL/TLS sessions not vulnerable to man-in-the-middle attacks.
</p>

vvv

Don't reinvent the wheel by implementing custom certificate chain validation.

<pre>
<code data-line-numbers="">
import requests

requests.request('GET', 'https://example.domain', verify=False) # Noncompliant
requests.get('https://example.domain', verify=False) # Noncompliant
</code>
</pre>

<div class="fragment">

TLS libraries provide built-in certificate validation functions that should be used.

<pre>
<code data-line-numbers="">
import requests

requests.request('GET', 'https://example.domain', verify=True)
requests.request('GET', 'https://example.domain', verify='/path/to/CAbundle')
requests.get(url='https://example.domain') # by default certificate validation is enabled
</code>
</pre>

</div>

>>>

#### 2.4 Cryptographic key generation should be based on strong parameters

<p class="fragment">
When generating cryptographic keys (or key pairs), it is important to use strong parameters. Key length, for instance, should provide enough entropy against brute-force attacks.
</p>

vvv

<p class="fragment">
For RSA and DSA algorithms key size should be at least <span style="color:green">2048</span> bits long
</p>

<p class="fragment">
For ECC (elliptic curve cryptography) algorithms key size should be at least <span style="color:green">224</span> bits long
</p>

<p class="fragment">
For RSA public key exponent should be at least <span style="color:green">65537</span>.
</p>

vvv

Unsafe

<pre>
<code data-line-numbers="|4-5">
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

dsa.generate_private_key(key_size=1024, backend=backend) # Noncompliant
rsa.generate_private_key(public_exponent=999, key_size=2048, backend=backend) # Noncompliant
</code>
</pre>

<div class="fragment">

Safe

<pre>
<code data-line-numbers="|4-5">
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

dsa.generate_private_key(key_size=2048, backend=backend) # Compliant
rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend) # Compliant
</code>
</pre>

</div>


>>>

#### 2.5 Using non-standard cryptographic algorithms is security-sensitive

<p class="fragment">
The use of a non-standard algorithms is dangerous because a determined attacker may be able to break the algorithm and compromise it.
</p>

<p class="fragment" style="color:green">
Use a standard algorithm instead of creating a custom one.
</p>

>>>

#### 2.6 Using weak hashing algorithms is security-sensitive

<p class="fragment">
Cryptographic hash algorithms such as MD2, MD4, MD5, SHA-1 (and many others) are no longer considered secure.
</p>

<p class="fragment" style="color:red">
These algorithms make it possible to have hash collisions - two inputs can be found that produce the same hash.
</p>

vvv

Safer alternatives, such as SHA-256, SHA-512, SHA-3 are recommended.

<p class="fragment">
For password hashing, it's better to use algorithms that do not compute too "quickly" because it slows down brute force attacks.
</p>

vvv

Don't use weak hasing algorithms

<pre>
<code data-line-numbers="|3">
import hashlib
m = hashlib.sha1() // Sensitive
</code>
</pre>

<div class="fragment">

Use stronger ones

<pre>
<code data-line-numbers="|3">
import hashlib
m = hashlib.sha512() // Compliant
</code>
</pre>

</div>

>>>

#### 2.7 JWT should be signed and verified

<p class="fragment">
If a JSON Web Token (JWT) is not signed with a strong cipher algorithm (or not signed at all) an attacker can forge it and impersonate user identities.
</p>

<div class="fragment">

<pre>
<code data-line-numbers="">
jwt.decode(token, verify = False)  # Noncompliant
jwt.decode(token, key, options={"verify_signature": False})  # Noncompliant
</code>
</pre>

</div>

vvv

Ensure JWT tokens are strongly signed.

<pre>
<code data-line-numbers="">
jwt.decode(token, key, algo) #Compliant
</code>
</pre>

>>>

#### 2.8 Using pseudorandom number generators (PRNGs) is security-sensitive

When software generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated.

vvv

<p class="fragment">
Only use random number generators which are <span style="color:green">recommended by OWASP</span> or any other trusted organization.
</p>

<p class="fragment">
Use the generated random values <span style="color:green">only once</span>.
</p>

<p class="fragment">
<span style="color:green">Do not expose</span> the generated random value.
</p>

>>>

#### 2.9 Hashes should include an unpredictable salt

<p class="fragment">
In cryptography, a "salt" is an extra piece of data which is included when hashing a password. This makes rainbow-table attacks more difficult.
</p>

<p class="fragment">
Use hashing functions generating their <span style="color:green">own secure salt</span> or generate a secure random value of at least 16 bytes. 
</p>

<p class="fragment">
The salt should be <span style="color:green">unique per password</span>.
</p>

vvv

<span style="color:red">Salt is hard-coded</span>

<pre>
<code data-line-numbers="|5">
import crypt
from hashlib import pbkdf2_hmac

hash = pbkdf2_hmac('sha256', password, b'D8VxSmTZt2E2YV454mkqAY5e', 100000)    # Noncompliant: salt is hardcoded
</code>
</pre>

<div class="fragment">

<span style="color:green">Different salt per hash</span>

<pre>
<code data-line-numbers="|5-6">
import crypt
from hashlib import pbkdf2_hmac

salt = os.urandom(32)
hash = pbkdf2_hmac('sha256', password, salt, 100000)    # Compliant
</code>
</pre>

</div>

>>>

#### 2.10 Using clear-text protocols is security-sensitive

<p class="fragment">
Clear-text protocols such as ftp, telnet or non-secure http lack encryption of transported data, as well as the capability to build an authenticated connection.
</p>

<p class="fragment">
An attacker may be able to <span style="color:red">sniff and manipulate traffic</span>.
</p>

vvv

Sensitive

<pre>
<code data-line-numbers="">
url = "http://example.com" # Sensitive
url = "ftp://anonymous@example.com" # Sensitive
url = "telnet://anonymous@example.com" # Sensitive
</code>
</pre>

<div class="fragment">

Safe

<pre>
<code data-line-numbers="">
url = "https://example.com" # Compliant
url = "sftp://anonymous@example.com" # Compliant
url = "ssh://anonymous@example.com" # Compliant
</code>
</pre>

</div>

>>>

## OWASP Vulnerabilities 2021

1. Broken Access Control
2. Cryptographic Failures
3. <span style="color:#FFFFA7">Injection</span>
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery


>>>

<span style="color:#FFFFA7">**Injection**</span>

<p class="fragment">
One vector of attack for any application is external data, which can be used for injection, XSS, or denial of service (DOS) attacks
</p>

<p class="fragment" style="color:red">
Treat external data with suspicion 
</p>

>>>

#### 3.1 I/O function calls should not be vulnerable to path injection attacks

See 1.5

>>>

#### 3.2 Regular expressions should not be vulnerable to Denial of Service attacks

<p class="fragment">
Most regular expression engines use <span style="color:red">backtracking</span> to try all possible execution paths of a regular expression.
</p>

<p class="fragment">
In some cases it can cause performance issues, called <span style="color:red">catastrophic backtracking situations</span>
</p>

vvv

Do not construct a regular expression pattern from a user input.

<p class="fragment">
If you must, <span style="color:green">sanitize the input</span>.
</p>

<div class="fragment">

<pre>
<code data-line-numbers="|7">
from flask import request
import re

@app.route('/upload')
def upload():
    username = re.escape(request.args.get('username'))
    filename = request.files.get('attachment').filename

    re.search(username, filename) # Compliant
</code>
</pre>
</div>


>>>

#### 3.3 OS commands should not be vulnerable to command injection attacks

<p class="fragment">
Failure to sanitize user input used for OS commands could allow an attacker to include input that <span style="color:red">executes unintended commands or exposes sensitive data</span>.
</p>

vvv

Unsafe

<pre>
<code data-line-numbers="|8">
from flask import request
import os

@app.route('/ping')
def ping():
    address = request.args.get("address")
    cmd = "ping -c 1 %s" % address
    os.popen(cmd) # Noncompliant
</code>
</pre>

<div class="fragment">

Safe

<pre>
<code data-line-numbers="|7">
from flask import request
import os

@app.route('/ping')
def ping():
    address = shlex.quote(request.args.get("address")) # address argument is shell-escaped
    cmd = "ping -c 1 %s" % address
    os.popen(cmd ) # Compliant
</code>
</pre>

</div>

>>>

#### 3.4 Dynamic code execution should not be vulnerable to injection attacks

<p class="fragment">
Applications that execute code dynamically should neutralize any externally-provided values used to construct the code.
</p>

<p class="fragment" style="color:green">
Whitelist allowed values or cast to safe types.
</p>

vvv

Unsafe

<pre>
<code data-line-numbers="|7">
from flask import request

@app.route('/')
def index():
    module = request.args.get("module")
    exec("import urllib%s as urllib" % module) # Noncompliant
</code>
</pre>

<div class="fragment">

Safe

<pre>
<code data-line-numbers="|7">
from flask import request

@app.route('/')
def index():
    module = request.args.get("module")
    exec("import urllib%d as urllib" % int(module)) # Compliant; module is safely cast to an integer
</code>
</pre>

</div>

>>>

#### 3.5 HTTP responses should not be vulnerable to session fixation

<p class="fragment">
Constructing cookies directly from tainted data enables attackers to set the session identifier to a known value
</p>

<p class="fragment" style="color:red">
Successful attacks might result in unauthorized access to sensitive information.
</p>

vvv

Unsafe

<pre>
<code data-line-numbers="|5-6">
def index(request):
    value = request.GET.get("value")
    response = HttpResponse("")
    response["Set-Cookie"] = value  # Noncompliant
    response.set_cookie("sessionid", value)  # Noncompliant
    return response
</code>
</pre>

<div class="fragment">

Restrict the cookies that can be influenced with an allow-list.

<pre>
<code data-line-numbers="|5-6">
def index(request):
    value = request.GET.get("value")
    response = HttpResponse("")
    response["X-Data"] = value
    response.set_cookie("data", value)
    return response
</code>
</pre>

</div>

>>>

#### 3.6 Disabling auto-escaping in template engines is security-sensitive

<p class="fragment">
To reduce the risk of cross-site scripting attacks, templating systems escape characters that may make sense to a browser, and hijack it.
</p>

<p class="fragment">
(eg: <span style="color:red">&lta&gt</span>) will be transformed/replaced with escaped/sanitized values (eg: <span style="color:green">& lt;a& gt;</span> )
</p>

vvv

Ensure autoescape is not disabled

<pre>
<code data-line-numbers="|5">
from jinja2 import Environment

env = Environment() # Sensitive: New Jinja2 Environment has autoescape set to false
env = Environment(autoescape=False) # Sensitive:
</code>
</pre>

<div class="fragment">

Safe

<pre>
<code data-line-numbers="|3">
from jinja2 import Environment
env = Environment(autoescape=True) # Compliant
</code>
</pre>

</div>


>>>

#### 3.7 XPath expressions should not be vulnerable to injection attacks

<p class="fragment">
Constructing XPath expressions directly from tainted data enables attackers to inject specially crafted values that changes the initial meaning of the expression itself.
</p>

<p class="fragment" style="color:red">
Successful XPath injection attacks can read sensitive information from XML documents.
</p>

vvv

Unsafe

<pre>
<code data-line-numbers="0-10|4-5">
@app.route('/user')
def user_location():
    username = request.args['username']
    query = "./users/user/[@name='" + username + "']/location"
    elmts = root.findall(query) # Noncompliant
    return 'Location %s' % list(elmts)
</code>
</pre>

<div class="fragment">

Safe

<pre>
<code data-line-numbers="0-10|4-5">
@app.route('/user')
def user_location():
    username = request.args['username']
    query = "/collection/users/user[@name = $paramname]/location/text()"
    elmts = root.xpath(query, paramname = username)
    return 'Location %s' % list(elmts)
</code>
</pre>

</div>

>>>

#### 3.8 Endpoints should not be vulnerable to reflected cross-site scripting (XSS) attacks

<p class="fragment">
When processing a HTTP request, a web server may copy user-provided data into the body of the HTTP response that is sent back to the user.
</p>

<p class="fragment" style="color:red">
Endpoints reflecting tainted data could allow attackers to inject code that would eventually be executed in the user's browser
</p>

vvv

Unsafe

<pre>
<code data-line-numbers="">
<title>Hello from Flask</title>
{% if name %}
  <h1>Hello {{ name }}!</h1>
{% else %}
  <h1>Hello, World!</h1>
{% endif %}
</code>
</pre>

<pre>
<code data-line-numbers="0-10|7">
@xss.route('/insecure/no_template_engine_replace', methods =['GET'])
def no_template_engine_replace():
    param = request.args.get('param', 'not set')

    html = open('templates/xss_shared.html').read()
    response = make_response(html.replace('{{ name }}', param)) # Noncompliant: param is not sanitized
    return response
</code>
</pre>

vvv

Safe

<pre>
<code data-line-numbers="">
<title>Hello from Flask</title>
{% if name %}
  <h1>Hello {{ name }}!</h1>
{% else %}
  <h1>Hello, World!</h1>
{% endif %}
</code>
</pre>

<pre>
<code data-line-numbers="0-10|6">
@xss.route('/secure/no_template_engine_sanitized_Markup_escape', methods =['GET'])
def no_template_engine_sanitized_Markup_escape():
    param = request.args.get('param', 'not set')

    param = Markup.escape(param)

    html = open('templates/xss_shared.html').read()
    response = make_response(html.replace('{{ name }}', param )) # Compliant: 'param' is sanitized by Markup.escape
    return response
</code>
</pre>

>>>

#### 3.9 Database queries should not be vulnerable to injection attacks

<p class="fragment">
Constructing SQL queries directly from tainted data enables attackers to inject specially crafted values that change the initial meaning of the query itself
</p>

<p class="fragment" style="color:red">
Successful database query injection attacks can read, modify, or delete sensitive information
</p>

vvv

User data can change the meaning of the SQL statement

<pre>
<code data-line-numbers="|10">
from flask import request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from database.users import User

@app.route('hello')
def hello():
    id = request.args.get("id")
    stmt = text("SELECT * FROM users where id=%s" % id) # Query is constructed based on user inputs
    query = SQLAlchemy().session.query(User).from_statement(stmt) # Noncompliant
    user = query.one()
    return "Hello %s" % user.username
</code>
</pre>

vvv

Protect with prepared statements

<pre>
<code data-line-numbers="|10-11">
from flask import request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from database.users import User

@app.route('hello')
def hello():
    id = request.args.get("id")
    stmt = text("SELECT * FROM users where id=:id")
    query = SQLAlchemy().session.query(User).from_statement(stmt).params(id=id) # Compliant
    user = query.one()
    return "Hello %s" % user.username
</code>
</pre>

>>>

#### 3.10 NoSQL operations should not be vulnerable to injection attacks

<p class="fragment">
Applications that perform NoSQL operations based on tainted data can be exploited similarly to regular SQL injection bugs
</p>

vvv

Parameters influenced by user-controlled values may result in unexpected NoSQL operations.

<p class="fragment" style="color:green">
Use an Object Domain Mapper, or validate user input, to mitigate.
</p>

>>>

#### 3.11 Constructing arguments of system commands from user input is security-sensitive

See 3.3

>>>

#### 3.12 HTTP response headers should not be vulnerable to injection attacks

<p class="fragment">
Web application frameworks and servers might also allow attackers to inject new line characters in headers to craft malformed HTTP response
</p>

vvv

Malformed headers can result in HTTP Response Splitting/Smuggling

<pre>
<code data-line-numbers="|4,7">
@app.route('/route')
def route():
    content_type = request.args["Content-Type"]
    response = Response()
    headers = Headers()
    headers.add("Content-Type", content_type) # Noncompliant
    response.headers = headers
    return response
</code>
</pre>

vvv

Validate the headers against a whitelist, to ensure compliance.

<pre>
<code data-line-numbers="|8-11">
@app.route('/route')
def route():
    content_type = request.args["Content-Type"]
    allowed_content_types = r'application/(pdf|json|xml)'
    response = Response()
    headers = Headers()
    if re.match(allowed_content_types, content_type):
        headers.add("Content-Type", content_type)  # Compliant
    else:
        headers.add("Content-Type", "application/json")
    response.headers = headers
    return response
</code>
</pre>

>>>

#### 3.13 Dynamically executing code is security-sensitive

<p class="fragment">
APIs that enable the execution of dynamic code by providing it as strings at runtime, increase the risk of code injection.
</p>

vvv

<span style="color:red">Avoid code injection</span>

<pre>
<code data-line-numbers="|6,8,11,12,14">
value = input()
command = 'os.system("%s")' % value

def evaluate(command, file, mode):
    eval(command)  # Sensitive.

eval(command)  # Sensitive. Dynamic code

def execute(code, file, mode):
    exec(code)  # Sensitive.
    exec(compile(code, file, mode))  # Sensitive.

exec(command)  # Sensitive.
</code>
</pre>

>>>

## OWASP Vulnerabilities 2021

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. <span style="color:#FFFFA7">Insecure Design</span>
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery

>>>

<span style="color:#FFFFA7">**Insecure Design**</span>

<p class="fragment">
Insecure design is a broad category representing different weaknesses, expressed as "missing or ineffective control design." 
</p>

<p class="fragment">
There is a difference between insecure design and insecure implementation.
</p>

>>>

#### 4.1 Allowing both safe and unsafe HTTP methods is security-sensitive

See 1.2

>>>

#### 4.2 Setting loose POSIX file permissions is security-sensitive

See 1.4

>>>

#### 4.3 Creating cookies without the "secure" flag is security-sensitive

<p class="fragment">
When a cookie is protected with the <span style="color:green">secure</span> attribute set to true it will not be send by the browser over an unencrypted HTTP channel.
</p>

<p class="fragment" style="color:green">
This protects against man-in-the-middle attacks.
</p>

vvv

Beware, secure cookies are often not the default behaviour

<pre>
<code data-line-numbers="|5">
@app.route('/')
def index():
    response = Response()
    response.set_cookie('key', 'value') # Sensitive
    return response
</code>
</pre>

<div class="fragment">

Use the ```secure``` flag and HTTPS as a rule.

<pre>
<code data-line-numbers="|5">
@app.route('/')
def index():
    response = Response()
    response.set_cookie('key', 'value', secure=True) # Compliant
    return response
</code>
</pre>

</div>

>>>

## OWASP Vulnerabilities 2021

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. <span style="color:#FFFFA7">Security Misconfiguration</span>
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery

>>>

<span style="color:#FFFFA7">**Security Misconfiguration**</span>

<p class="fragment">
Improperly configured permissions on cloud services
</p>

<p class="fragment">
Unnecessary features enabled by default
</p>

<p class="fragment">
Default passwords and accounts
</p>

<p class="fragment">
Over informative errors
</p>

<p class="fragment">
Old software
</p>

>>>

#### 5.1 Delivering code in production with debug features activated is security-sensitive

<p class="fragment">
In a development environment, it makes sense to have verbose error messages.
</p>

<p class="fragment">
In production, you want to <span style="color:green">prevent any leaks of information</span> that might help an attacker to learn more about your environment
</p>

vvv

By default, most frameworks have debugging switched on.

<div class="fragment">

For example, Django has it enabled in settings.py.

<pre>
<code data-line-numbers="|5-6">
# NOTE: The following code raises issues only if the file is named "settings.py" or "global_settings.py". This is the default
# name of Django configuration file

DEBUG = True  # Sensitive
DEBUG_PROPAGATE_EXCEPTIONS = True  # Sensitive
</code>
</pre>

</div>


>>>

#### 5.2 Server hostnames should be verified during SSL/TLS connections

See 2.2

>>>

#### 5.3 Server certificates should be verified during SSL/TLS connections

See 2.3

>>>

#### 5.4 Creating cookies without the "secure" flag is security-sensitive

See 4.3

>>>

#### 5.5 Having a permissive Cross-Origin Resource Sharing policy is security-sensitive

<p class="fragment">
Same origin policy (in browsers) prevents a JavaScript frontend to perform a cross-origin HTTP request to a resource that has a different origin (domain, protocol, or port) from its own.	
</p>

vvv

Permissive CORS is security-sensitive

<pre>
<code data-line-numbers="|6">
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "send_wildcard": "True"}}) # Sensitive
</code>
</pre>

<div class="fragment">

Ban sending wildcard responses

<pre>
<code data-line-numbers="|6">
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "send_wildcard": "False"}}) # Compliant
</code>
</pre>

</div>

>>>

#### 5.6 Creating cookies without the "HttpOnly" flag is security-sensitive

<p class="fragment">
When a cookie is configured with the HttpOnly attribute set to true, the browser guaranties that no client-side script will be able to read it.
</p>

<p class="fragment">
The default value of HttpOnly is <span style="color:red">false</span>
</p>

vvv

When creating a cookie that may contain sensitive information, <span style="color:green">set httponly to true</span>.

<pre>
<code data-line-numbers="|7">
from flask import Response

@app.route('/')
def index():
    response = Response()
    response.set_cookie('key', 'value', httponly=True) # Compliant
    return response
</code>
</pre>


>>>

#### 5.7 XML parsers should not be vulnerable to XXE attacks

<p class="fragment">
XML standard allows the use of entities which can be internal or external
</p>

<p class="fragment">
When parsing the XML file, the content of the external entities is retrieved from an external storage such as the file system or network, which <span style="color:red">may lead to vulnerabilities<style>.
</p>

vvv

Unsafe

<pre>
<code data-line-numbers="|2,6">
parser = etree.XMLParser() # Noncompliant: by default resolve_entities is set to true
tree1 = etree.parse('ressources/xxe.xml', parser)
root1 = tree1.getroot()

parser = etree.XMLParser(resolve_entities=True) # Noncompliant
tree1 = etree.parse('ressources/xxe.xml', parser)
root1 = tree1.getroot()
</code>
</pre>

<div class="fragment">

<span style="color:green">Limit resolution of external entities</span>

<pre>
<code data-line-numbers="|2">
parser = etree.XMLParser(resolve_entities=False, no_network=True) # Compliant
tree1 = etree.parse('resources/xxe.xml', parser)
root1 = tree1.getroot()
</code>
</pre>

</div>

>>>

#### 5.8 Expanding archive files without controlling resource consumption is security-sensitive

See 1.7

>>>

## OWASP Vulnerabilities 2021

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. <span style="color:#FFFFA7">Vulnerable and Outdated Components</span>
7. Identification and Authentication Failures
8. Software and Data Integrity
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery

>>>

<span style="color:#FFFFA7">Vulnerable and Outdated Components</span>

<p class="fragment">
Unsupported software, libraries or other dependencies often introduce vulnerabilities.
<p>

>>>

#### 6.1 Upgrade, update, patch

You should always use up-to-date code to make sure that your software doesn't open doors for attackers.

<p class="fragment">
Python is no exception to this rule.
</p>

<p class="fragment">
Python 2 is <span style="color:red">EOL<span>
</p>

<p class="fragment">
Python 3.7, 3.8, 3.9 and 3.10 are <span style="color:green">actively supported</span>
</p>

>>>

#### 6.2 Scan your code

<p class="fragment">
Developers have a wide array of static code analysis tools at their disposal for maintaining Python security.
</p>

<p class="fragment">
Various tools are available such as <span style="color:blue">pep8</span>, <span style="color:blue">pylint</span>, <span style="color:blue">flake8</span>, and more.
</p>

<p class="fragment">
Tools like <span style="color:blue">bandit</span> transform code into an AST to detect security issues.
</p>

vvv

![](https://soshace.com/wp-content/uploads/2021/01/flaskappbandit.png)

>>>

#### 6.3 Review dependency licenses

<p class="fragment">
Open source projects are free and available to use, but there may still be terms and conditions applied
</p>

<p class="fragment">
You should become familiar with the open source licenses necessary for the projects you use, so you are sure that you are not compromising yourself legally.
</p>

>>>

#### 6.4 Check your spelling

<p class="fragment">
<span style="color:red">Typosquatting</span> has been known to occur on PyPi (and other package providers).
</p>

<p class="fragment">
A malicious actor may upload a compromised version of a package with a misspelt name.
</p>

<p class="fragment">
For example, rather than <span style="color:green">django</span> it may be named <span style="color:red">
jango</span>
</p>


>>>

#### 6.5 Avoid relative imports

<p class="fragment">
Python 2 allows implicit, relative, imports
</p>

<div class="fragment">

<pre>
<code data-line-numbers="2">
from .some_package import some_function
</code>
</pre>

</div>

<p class="fragment">
If the module specified is found in the system path, it will be imported and that could be very dangerous. 
</p>

vvv

If you are still using Python 2, ensure you remove the use of implicit relative imports.

<p class="fragment" style="color:green">
This as been removed in Python 3.
</p>


>>>

## OWASP Vulnerabilities 2021

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. <span style="color:#FFFFA7">Identification and Authentication Failures</span>
8. Software and Data Integrity
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery

>>>

<span style="color:#FFFFA7">Identification and Authentication Failures</span>

<p class="fragment">
Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.
<p>

>>>

#### 7.1 Weak SSL/TLS protocols should not be used

See 2.1

>>>

#### 7.2 A secure password should be used when connecting to a database

<p class="fragment">

When relying on the password authentication mode for the database connection, a secure password should be chosen.

</p>

vvv

<p style="color:red">Absent or weak credentials should be avoided</p>

<pre>
<code data-line-numbers="|3">
def configure_app(app):
  app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://user:@domain.com" # Noncompliant
</code>
</pre>

<div class="fragment">

<p style="color:green">Use a secure password</p>

<pre>
<code data-line-numbers="|3">
def configure_app(app, pwd):
    app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://user:{pwd}@domain.com" # Compliant
</code>
</pre>

</div>

>>>

#### 7.3 Credentials should be rotated on a frequent basis

<p class="fragment">
In addition to creating secure credentials, these credentials should be <span style="color:green">changed frequently</span>.
</p>

>>>

#### 7.4 LDAP connections should be authenticated

<p class="fragment">
Simple authentication in LDAP can be used with three different mechanisms:
</p>

<p class="fragment" style="color:red">
Anonymous 
</p>

<p class="fragment" style="color:red">
Unauthenticated
</p>

<p class="fragment" style="color:green">
Name/Password
</p>

vvv

Anonymous binds and unauthenticated binds allow access to information in the LDAP directory without providing a password.

<pre>
<code data-line-numbers="|6-9">
import ldap

def init_ldap():
   connect = ldap.initialize('ldap://example:1389')
   connect.simple_bind('cn=root') # Noncompliant
   connect.simple_bind_s('cn=root') # Noncompliant
   connect.bind_s('cn=root', None) # Noncompliant
   connect.bind('cn=root', None) # Noncompliant
</code>
</pre>

vvv

Safe

<pre>
<code data-line-numbers="|7-10">
import ldap
import os

def init_ldap():
   connect = ldap.initialize('ldap://example:1389')
   connect.simple_bind('cn=root', os.environ.get('LDAP_PASSWORD')) # Compliant
   connect.simple_bind_s('cn=root', os.environ.get('LDAP_PASSWORD')) # Compliant
   connect.bind_s('cn=root', os.environ.get('LDAP_PASSWORD')) # Compliant
   connect.bind('cn=root', os.environ.get('LDAP_PASSWORD')) # Compliant
</code>
</pre>

>>>

#### 7.5 Hard-coded credentials are security-sensitive

<div class="fragment">

Because it is easy to extract strings from an application source code or binary, credentials should not be hard-coded

</div>

<div class="fragment">

<pre>
<code data-line-numbers="">
username = 'admin'
password = 'admin' # Sensitive
usernamePassword = 'user=admin&password=admin' # Sensitive
</code>
</pre>

</div>

vvv

Read from configuration, or environment variables, instead

<pre>
<code data-line-numbers="|4-8">
import os

username = os.getenv("username") # Compliant
password = os.getenv("password") # Compliant
usernamePassword = 'user=%s&password=%s' % (username, password) # Compliant{code}
</code>
</pre>

>>>

#### 7.6 Mismanaged secrets

<p class="fragment">
Sometimes secrets can be forgotten about and then committed to a code repo.
</p>

<p class="fragment">
Make sure that anything you commit are free of secret information of any kind.
</p>

>>>

## OWASP Vulnerabilities 2021

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. <span style="color:#FFFFA7">Software and Data Integrity</span>
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery

>>>

<span style="color:#FFFFA7">Software and Data Integrity</span>

<p class="fragment">
Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.
<p>

>>>

#### 8.1 Be careful with downloaded packages

<p class="fragment">
<b>pip</b> makes it easy to install software packages.
</p>

<p class="fragment" style="color:red">
<b>pip</b> also makes it easy to introduce vulnerabilities
</p>

<p class="fragment">
Assume there are malicious packages within PyPI and you should act accordingly
</p>


>>>

#### 8.2 Do not use the system version of Python

<p class="fragment">
Most POSIX systems come preloaded with a version of Python
</p>

<p class="fragment" style="color:red">
More often than not, it is out of date
</p>

>>> 

#### 8.3 Use virtual or temporary (docker) environments for builds

<p class="fragment">
Using a virtual environment prevents having malicious Python dependencies in your projects.
</p>

vvv

<p>
If you have malicious packages in your Python environments, using a virtual environment will prevent having the same packages in your Python codebase
</p>

<div class="fragment">

<pre>
<code data-line-numbers="">
pip install virtualenv

virtualenv -p /path/to/python env_name
</code>
</pre>

</div>

>>>

#### 8.4 Deserialization should not be vulnerable to injection attacks

<p class="fragment">
Deserialization based on data supplied by the user could result in two types of attacks
</p>

<p class="fragment">
<span style="color:red">Remote code execution</span> attacks - the structure of the serialized data is changed to modify the behavior of the object. 
</p>

<p class="fragment">
<span style="color:red">Parameter tampering attacks</span> - data is modified to escalate privileges or alter information. 
</p>

vvv

Some deserializers allow <span style="color:red">unsafe</span> actions to be performed

<pre>
<code data-line-numbers="|9,14">
from flask import request
import pickle
import yaml

@app.route('/pickle')
def pickle_loads():
    file = request.files['pickle']
    pickle.load(file) # Noncompliant; Never use pickle module to deserialize user inputs

@app.route('/yaml')
def yaml_load():
    data = request.GET.get("data")
    yaml.load(data, Loader=yaml.Loader) # Noncompliant; Avoid using yaml.load with unsafe yaml.Loader
</code>
</pre>

vvv

Use the safety features of your deserialization technology.

Or use an inherently safe technology, such as JSON or Protocol Buffers.

<pre>
<code data-line-numbers="|8">
from flask import request
import yaml

@app.route('/yaml')
def yaml_load():
    data = request.GET.get("data")
    yaml.load(data) # Compliant;  Prefer using yaml.load with the default safe loader
</code>
</pre>

<p class="fragment">
This prevents the loading of custom classes but supports standard types like hashes and arrays.
</p>

>>>

## OWASP Vulnerabilities 2021

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity
9. <span style="color:#FFFFA7">Security Logging and Monitoring Failures</span>
10. Server-Side Request Forgery

>>>

<span style="color:#FFFFA7">Security Logging and Monitoring Failures</span>

<p class="fragment">
Detect, escalate, and respond to active breaches. 
<p>

<p class="fragment" style="color:red">
Without logging and monitoring, breaches cannot be detected.
</p>

>>>

#### 9.1 Don't display information users shouldn't see

<p class="fragment">
Debugging information on your production system is a <span style="color:red">security hazard</span>.
</p>

<p class="fragment">
Switch off any debugging information on the production systems that could be publicly visible.
</p>

<p class="fragment" style="color:green">
Users should see only a generalized explanation of the error if needed.
</p>

vvv

![](https://csharpcorner-mindcrackerinc.netdna-ssl.com/UploadFile/ajyadav123/exploiting-by-information-disclosure-in-Asp-Net/Images/server%20error.jpg)

>>>

#### 9.2 Don't rely on assert statements for validation

<p class="fragment">
Don't use assert statements to guard against pieces of code that a user shouldn't access.
</p>

<p class="fragment">
By default Python executes with __debug__ as true
</p>

<p class="fragment">
In a production environment, it's common to run with <span style="color:red">optimizations this will skip any assert statement</span>.
</p>

vvv

<pre>
<code data-line-numbers="|4">
is_superuser = False

assert is_superuser
# something sensitive
print("something sensitive")
</code>
</pre>

<div class="fragment">

By default assertions are applied

<pre>
<code data-line-numbers="|2,5">
python3 test.py
Traceback (most recent call last):
  File "test.py", line 3, in <module>
    assert is_superuser
AssertionError
</code>
</pre>

</div>

<div class="fragment">

When optimized, assertions are turned off

<pre>
<code data-line-numbers="|2,3">
python3 -O test.py
something sensitive
</code>
</pre>

</div>

>>>

#### 9.3 Logging should not be vulnerable to injection attacks

<p class="fragment">
Applications logging tainted data could enable an attacker to inject characters that would break the log file pattern.
</p>

<p class="fragment" style="color:red">
This could be used to block monitors and SIEM (Security Information and Event Management) systems from detecting other malicious events.
</p>

vvv

Unsafe

<pre>
<code data-line-numbers="|7,8">
from flask import request, current_app
import logging

@app.route('/log')
def log():
    input = request.args.get('input')
    current_app.logger.error("%s", input) # Noncompliant
</code>
</pre>

vvv

This problem could be mitigated by sanitizing the user-provided data before logging it.

<pre>
<code data-line-numbers="|8">
from flask import request, current_app
import logging

@app.route('/log')
def log():
    input = request.args.get('input')
    if input.isalnum():
        current_app.logger.error("%s", input) # Compliant
</code>
</pre>

<div class="fragment">
The isalnum() method returns True if all characters in the string are alphanumeric
</div>

>>>

#### 9.4 Configuring loggers is security-sensitive

<p class="fragment">
Logs are also a target for attackers because they might contain sensitive information
</p>

vvv

<p class="fragment">
<span style="color:green">Disable debug</span> logging in production until needed - avoids leaking sensitive information
</p>

<p class="fragment">
Ensure logs are <span style="color:green">secured</span>
</p>

<p class="fragment">
Check log <span style="color:green">permissions</span>
</p>

<p class="fragment">
Ensure logs <span style="color:green">rotate</span>, so to not fill up disks
</p>


>>>

## OWASP Vulnerabilities 2021

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity
9. Security Logging and Monitoring Failures</span>
10. <span style="color:#FFFFA7">Server-Side Request Forgery</span>

>>>

<span style="color:#FFFFA7">Server-Side Request Forgery</span>

<p class="fragment">
SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL
</p>

>>>

#### 10.1 Server-side requests should not be vulnerable to forging attacks

<p class="fragment">
Performing requests from user-controlled data could allow attackers to <span style="color:red">make arbitrary requests</span> on the internal network or to <span style="color:red">change their original meaning</span>.
</p>


vvv

Validate the user-provided data.

Redesign the application to not send requests based on user-provided data

vvv

Unsafe

<pre>
<code data-line-numbers="|7,8">
from flask import request
import urllib

@app.route('/proxy')
def proxy():
    url = request.args["url"]
    return urllib.request.urlopen(url).read() # Noncompliant
</code>
</pre>

vvv

Safe

<pre>
<code data-line-numbers="|5,10">
from flask import request
import urllib

DOMAINS_WHITELIST = ['domain1.com', 'domain2.com']

@app.route('/proxy')
def proxy():
    url = request.args["url"]
    if urllib.parse.urlparse(url).hostname in DOMAINS_WHITELIST:
        return urllib.request.urlopen(url).read()
</code>
</pre>

>>>

The End