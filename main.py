import sys

from netmiko import ConnectHandler
from argparse import ArgumentParser


def get_arguments():
    """Добавление аргументов"""
    parser = ArgumentParser(description='Description of your program')
    parser.add_argument("-i", "--ip", dest="host", help="Enter host IP address", required=True)
    parser.add_argument("-u", "--user", dest="username", help="Enter username", required=True)
    parser.add_argument("-p", "--password", dest="password", help="Enter password", required=True)

    args = parser.parse_args()
    if not args.host:
        print("Введите имя хоста")
    elif not args.username:
        print("Введите имя пользователя")
    elif not args.password:
        print("Введите пароль")
    else:
        return args.host, args.username, args.password


class AddDomains:
    def __init__(self, host, username, password):
        self.user_names = ['Stiven1', 'Stiven2']

        self.host = host

        self.linux = {
            'device_type': 'linux',
            'host': host,
            'username': username,
            'password': password,
            "fast_cli": False,
        }

        self.ssh = ConnectHandler(**self.linux)

    @staticmethod
    def read_domains():
        """Чтение файла domains.txt"""
        try:
            with open('domains/domains.txt', 'r') as f:
                domains = f.read().split('\n')
            return domains
        except Exception as ex:
            sys.exit(f"Exception read domains file: {ex}")

    def update_os(self):
        update = self.ssh.send_command(
            'sudo apt update -y; sudo apt install apache2 -y; sudo apt install certbot python3-certbot-apache -y;'
        )

    def add_hosts(self, domains):
        domains_str = " www.".join(domains)
        ip_domains = f'{self.host} www.{domains_str}'.replace(',', '')
        self.ssh.send_command(command_string=f'echo "{ip_domains}" >> /etc/hosts', max_loops=1000)

    def create_user(self, domains):
        for (first_name, domain_site) in zip(self.user_names, domains):
            domain = domain_site.replace(',', '')
            create_user = self.ssh.send_command(
                f'sudo useradd --create-home --home-dir /www/{domain} --shell /bin/bash --gid www-data --skel /etc/skel-www {first_name}'
            )

    def settings_http(self, domains):
        for site_domain in domains:
            try:
                code = """
                <VirtualHost *:80>
                    ServerName {domain}
                    ServerAlias www.{domain}
                    Redirect / https://{domain}
                    DocumentRoot "/www/{domain}/www/public_html"
                    <Directory "/www/{domain}/www/public_html">
                        Options -FollowSymLinks +MultiViews -Indexes
                        AllowOverride all
                        Require all granted
                    </Directory>
                    ErrorLog "/www/{domain}/www/logs/error.log"
                    CustomLog "/www/{domain}/www/logs/access.log" combined
                </VirtualHost>
                        """.format(domain=site_domain)
                self.ssh.send_command(
                    "echo '{code}' >> '/etc/apache2/sites-available/www.{domain}.conf'".format(
                        code=code, domain=site_domain)
                )
            except Exception as exc:
                print('Exception при настраивании Apache VirtualHost HTTP: ', exc)
                continue

    def settings_https(self, domains):
        for site_domain in domains:
            try:
                code = """
                <IfModule mod_ssl.c>
                <VirtualHost *:443>
                    ServerName {domain}
                    ServerAlias www.{domain}
                    DocumentRoot "/www/{domain}/www/public_html"
                    <Directory "/www/{domain}/www/public_html">
                        Options -FollowSymLinks +MultiViews -Indexes
                        AllowOverride all
                        Require all granted
                    </Directory>
                    ErrorLog "/www/{domain}/www/logs/error.log"
                    CustomLog "/www/{domain}/www/logs/access.log" combined
                SSLCertificateFile /etc/letsencrypt/live/{domain}/cert.pem
                SSLCertificateChainFile /etc/letsencrypt/live/{domain}/fullchain.pem
                SSLCACertificateFile /etc/letsencrypt/live/{domain}/chain.pem
                SSLCertificateKeyFile /etc/letsencrypt/live/{domain}/privkey.pem
                SSLHonorCipherOrder off
                SSLSessionTickets off
                </VirtualHost>
                </IfModule>
                """.format(domain=site_domain)
                self.ssh.send_command(
                    "echo '{code}' >> '/etc/apache2/sites-available/www.{domain}-ssl.conf'".format(
                        code=code, domain=site_domain)
                )
            except Exception as exc:
                print('Exception при настраивании Apache VirtualHost HTTPS: ', exc)
                continue

    def run(self):
        self.ssh.enable()

        domains = self.read_domains()
        self.update_os()
        self.add_hosts(domains)
        self.create_user(domains)
        self.settings_http(domains)
        self.settings_https(domains)


if __name__ == '__main__':
    host, username, password = get_arguments()
    add_domains = AddDomains(host, username, password)
    add_domains.run()

