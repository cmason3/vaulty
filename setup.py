import sys, pathlib
from setuptools import setup

for line in open('vaulty.py'):
  if line.startswith('__version__'):
    exec(line)
    break

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

install_requires = ["cryptography>=2.7"]

if sys.version_info[0] == 3 and sys.version_info[1] == 6:
  install_requires = ["cryptography>=2.7,<37.0"]

setup(
  name="pyvaulty",
  version=__version__,
  python_requires=">=3.6",
  description="Encrypt/Decrypt with ChaCha20-Poly1305",
  long_description=README[README.find('#'):],
  long_description_content_type="text/markdown",
  url="https://github.com/cmason3/vaulty",
  author="Chris Mason",
  author_email="chris@netnix.org",
  license="MIT",
  classifiers=[
    "Development Status :: 5 - Production/Stable",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3"
  ],
  packages=["vaulty"],
  include_package_data=True,
  install_requires=install_requires,
  entry_points={
    "console_scripts": [
      "vaulty=vaulty:main",
    ]
  }
)
