"""Setup script for socratic-security package"""
from setuptools import setup, find_packages

setup(
    name="socratic-security",
    version="0.1.0",
    description="Enterprise-grade security utilities for the Socrates AI platform",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Nireus AI",
    author_email="contact@nireus.ai",
    url="https://github.com/Nireus79/Socratic-security",
    license="MIT",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "regex>=2023.0.0",
        "pydantic>=2.0.0",
        "bleach>=6.0.0",
        "cryptography>=46.0.0",
        "psutil>=5.9.0",
    ],
    extras_require={
        "sandbox": ["docker>=6.0.0"],
        "mfa": ["pyotp>=2.9.0", "qrcode>=7.4.2"],
        "database": ["sqlalchemy>=2.0.0"],
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "ruff>=0.1.0",
            "mypy>=1.5.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
)
