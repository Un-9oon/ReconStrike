from setuptools import setup, find_packages

setup(
    name="reconstrike",
    version="3.0.0",
    description="Advanced Web & Network Vulnerability Assessment Framework",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="CypherSec",
    author_email="cyphersec.404@gmail.com",
    url="https://github.com/cyphersec-404/ReconStrike",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "urllib3>=2.0.0",
        "colorama>=0.4.6",
        "jinja2>=3.1.0",
        "python-nmap>=0.7.1",
        "dnspython>=2.4.0",
        "requests[socks]>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "reconstrike=reconstrike:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
    ],
)
