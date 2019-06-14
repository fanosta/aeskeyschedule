import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aeskeyschedule",
    version="0.0.2",
    entry_points = {
        'console_scripts': [
            'aeskeyschedule = aeskeyschedule.main:main'
        ],
    },
    author="fanosta",
    author_email="fanosta@users.noreply.github.com",
    description="Tool to calculate the Rijndael key schedule given any AES-128 round key.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fanosta/aeskeyschedule",
    packages=setuptools.find_packages(),
    install_requires=['colorama>=0.4.1'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
