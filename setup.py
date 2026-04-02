from setuptools import setup, find_packages

setup(
    name="dexenc",
    version="1.0.0",
    py_modules=["dexenc"],
    packages=find_packages(),
    install_requires=[
        "Pillow",
        "pycryptodome",
    ],
    entry_points={
        "console_scripts": [
            "dexenc=dexenc:main",
        ],
    },
)