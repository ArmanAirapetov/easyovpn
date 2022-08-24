# easyovpn
<p>That script helps automized process of configuring an openvpn server. The script probably runs only on Linux because it was tested on Debian and Ubuntu.</p>
<p>
It initializes a PKI, creates a CA (ca.crt). 
It creates a openvpn server key and a tls-crypt-v2 key, signs a openvpn server certificate, generates a Diffie-Hellman file.
Command <b><i>--init/-i</i></b> does these steps.
</p>
<p>
After previous steps it can make an individual .ovpn file for each client. Commands <b><i>--address/-a</i></b> and <b><i>--gen-clients/-gc</i></b>.
</p>
<h3>Installing</h3>
<ol>
  <li>
    <p>Download and install openvpn using <a href="https://community.openvpn.net/openvpn/wiki/OpenvpnSoftwareRepos">this guide</a>.</p> 
  </li>
  <li>
    <p>Download this repo.</p>
  </li>
  <li>
    <code>pip install -r requirements.txt</code>
  </li>
</ol>
<h3>First using</h3>
<ol>
  <li>
    <code>
      python easyovpn.py --init
    </code>
  </li>
  <li>
    <p>Go through interaction with the programm. It is easy I hope.
  </li>
</ol>
<h3>Next using</h3>
<code>
python easyovpn.py --address your_server_address --gen-clients num_of_new_clients
</code>
<h3>Combined</h3>
<code>
python easyovpn.py --init --address your_server_address --gen-clients num_of_new_clients
</code>

<p>The script was written based on <a href="https://simplificandoredes.com/en/install-open-vpn-on-linux/">this arcticle<a>. Thanks the author.</p>
