<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/NDJSec/AndroSleuth">
    <img src="images/logo.jpeg" alt="Logo" width="500" height="500">
  </a>

<h3 align="center">AndroSleuth</h3>

  <p align="center">
    A static and dynamic APK analysis tool built on AndroGuard 
    <br />
    <a href="https://github.com/NDJSec/AndroSleuth"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/NDJSec/AndroSleuth/issues">Report Bug</a>
    ·
    <a href="https://github.com/NDJSec/AndroSleuth/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>
<br>

## Android Reverse Engineering PDF [HERE](https://github.com/NDJSec/Android-Reverse-Engineering)
<br>

## Android Reverse Engineering Tools [DroidAnalysis](https://github.com/NDJSec/DroidAnalysis)
<br>

<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]](https://example.com)

AndroSleuth is a tool built on top of AndroGuard and Frida for automating static and dynamic analysis. This tool was designed to test for automatically test for cryptographic misuse in apps, but can be expanded to do much more.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

* [![Python][Python]][Python-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started
!TODO

### Prerequisites
* Python 3.12 or higher

### Installation
```bash
git clone git@github.com:NDJSec/AndroSleuth.git

cd AndroSleuth/andro_sleuth
python -m venv <envname>
source <envname>/bin/activate

pip install -e .
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

```bash
$ AndroSleuth -h
usage: AndroSleuth [-h] -f FILE [-j] [-x] [-d DIR]

Analyse Android Apps for broken SSL certificate validation.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  APK File to check
  -j, --java            Show Java code for results for non-XML output
  -x, --xml             Print XML output
  -d DIR, --dir DIR     Store decompiled App's Java code for further analysis in dir
```

_For more examples, please refer to the [Documentation](https://example.com)_

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

- [ ] Feature 1
- [ ] Feature 2
- [ ] Feature 3
    - [ ] Nested Feature

See the [open issues](https://github.com/NDJSec/AndroSleuth/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

NDJSec - [@NicolasJanis1](https://twitter.com/NicolasJanis1) - nicolas.d.janis@gmail.com

Project Link: [https://github.com/NDJSec/AndroSleuth](https://github.com/NDJSec/AndroSleuth)

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [Frdia](https://frida.re/)
* [AndroGuard](https://github.com/androguard/androguard)
* [Mallodroid](https://github.com/sfahl/mallodroid)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/NDJSec/AndroSleuth.svg?style=for-the-badge
[contributors-url]: https://github.com/NDJSec/AndroSleuth/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/NDJSec/AndroSleuth.svg?style=for-the-badge
[forks-url]: https://github.com/NDJSec/AndroSleuth/network/members
[stars-shield]: https://img.shields.io/github/stars/NDJSec/AndroSleuth.svg?style=for-the-badge
[stars-url]: https://github.com/NDJSec/AndroSleuth/stargazers
[issues-shield]: https://img.shields.io/github/issues/NDJSec/AndroSleuth.svg?style=for-the-badge
[issues-url]: https://github.com/NDJSec/AndroSleuth/issues
[license-shield]: https://img.shields.io/github/license/NDJSec/AndroSleuth.svg?style=for-the-badge
[license-url]: https://github.com/NDJSec/AndroSleuth/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/nicolas-janis/
[product-screenshot]: images/screenshot.png
[Python]: https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54
[Python-url]: https://www.python.org/