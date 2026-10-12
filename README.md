This repository if for peer review aimed at the Nym team and third-party Nym developers, to make a future WWW within the Nym Mixnet production ready, without modifying web browsers or web servers.

Download the [Nym repository](https://github.com/nymtech/nym) and place the web_proxy folder in /sdk/rust/nym-sdk/ and replace the original Cargo.toml with this Cargo.toml.

Nym Mixnet Web Server Alice:

http://976fc2fdad20aafa9c778390215691b358f52e4907c92e309933d38e4abd656152d7260d3ab08e19ee9a5b775ca546648d0f590e1b0d33d3022bba925904072d1fc394a4e26c4053b95ed6e00063c8b634917dc0fd5d2bb6a112f0ef6d65e968/

Nym Mixnet Web Server Bob:

http://31dde123ead24ad22c6d39ff27ce8a7d1d6be3aa45952f0dc096d6990e34471a0e121261c65817e99438707d612cb7b844da6e90c4a60b187d5f51129ff4e0434f0b3ac9d47db13c71de11c359f9c4fb783883f336f126e9d1311b48f98205dd/

To test the provided Nym Mixnet URLs with a web browser, simply download a binary of nym-web-proxy for your operating system, start it and set in your web browser settings http proxy port to 127.0.0.1:8081 and paste the URL in your web browser. To run your own web server in the Nym Mixnet let it listen on http port 8080 and start the official nym-proxy-server Linux binary and use nym-address-encoder for your http Nym Mixnet URL. That's all!
