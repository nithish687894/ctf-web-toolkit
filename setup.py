from setuptools import setup, find_packages

setup(
    name="ctf-web-toolkit",
    version="3.0.0",
    author="Nithishkumar S",
    description="Modular CTF web security testing suite",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/nithish687894/ctf-web-toolkit",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["requests>=2.28.0", "urllib3>=1.26.0"],
    entry_points={
        "console_scripts": [
            "ctf-toolkit=ctf_toolkit.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
