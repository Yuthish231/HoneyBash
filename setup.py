from setuptools import setup, find_packages

setup(
    name="honeybash",
    version="1.0.0",
    description="Multi-protocol Honeypot Framework in Python",
    author="HoneyBash Team",
    packages=find_packages(),
    install_requires=[
        "twisted>=24.0.0",
        "dnspython>=2.6.0",
        "paramiko>=3.4.0",
        "pyOpenSSL>=24.0.0",
        "cryptography>=42.0.0",
        "psutil>=5.9.0",
        "netifaces2>=0.0.22",
        "impacket>=0.11.0",
        "redis>=5.0.0",
        "pymysql>=1.1.0",
        "zope.interface>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "honeybash=HoneyBash.__main__:main_logic",
        ],
    },
    python_requires=">=3.9",
)
