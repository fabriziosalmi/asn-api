from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="asn-api-sdk",
    version="0.1.0",
    author="Fabrizio Salmi",
    author_email="fabrizio.salmi@gmail.com",
    description="Official Python SDK for the ASN Risk Intelligence Platform API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fabriziosalmi/asn-api",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
        "pydantic>=2.0.0",
    ],
)
