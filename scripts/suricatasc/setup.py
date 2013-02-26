#!/usr/bin/env python
from distutils.core import setup

SURICATASC_VERSION = "0.9"

setup(name='suricatasc',
      version=SURICATASC_VERSION,
      description='Suricata unix socket client',
      author='Eric Leblond',
      author_email='eric@regit.org',
      url='https://www.suricata-ids.org/',
      scripts=['suricatasc'],
      packages=['suricatasc'],
      package_dir={'suricatasc':'src'},
      provides=['suricatasc'],
      requires=['argparse','simplejson'],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Environment :: Console',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: GNU General Public License (GPL)',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Topic :: System :: Systems Administration',
          ],
      )
