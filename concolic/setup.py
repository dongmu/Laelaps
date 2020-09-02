from setuptools import setup
# from sys import version_info


setup(
    name='concolic_iot',
    version='0.0.1',
    packages=['concolic',
              ],
    install_requires=[
        'capstone>=3.0.4',
        'keystone-engine',
    ],
    description='Concolic execution for arbitrary ARM firmware execution'
)
