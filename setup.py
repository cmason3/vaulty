import pathlib
from setuptools import setup

for line in open('vaulty.py'):
  if line.startswith('__version__'):
    exec(line)
    break

HERE = pathlib.Path(__file__).parent

README = (HERE / "README.md").read_text()

setup(
  name="pyvaulty",
  version=__version__,
  description="Encrypt/Decrypt with ChaCha20-Poly1305",
  long_description=README[README.find('#'):],
  long_description_content_type="text/markdown",
  url="https://github.com/cmason3/vaulty",
  author="Chris Mason",
  author_email="chris@netnix.org",
  license="MIT",
  classifiers=[
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3"
  ],
  packages=["vaulty"],
  include_package_data=True,
  install_requires=["cryptography>=2.7"],
  entry_points={
    "console_scripts": [
      "vaulty=vaulty:main",
    ]
  }
)
