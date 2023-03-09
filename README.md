# CHOP - Catch Handler Oriented Programming

<a href="https://download.vusec.net/papers/chop_ndss23.pdf"> <img title="" src="https://user-images.githubusercontent.com/22239495/211558661-ed29d9f5-cc99-471b-b255-ee8ad523b297.png" alt="CHOP paper thumbnail" align="right" width="200"></a>

This repository contains the source code release accompanying our paper "Let Me Unwind That For You: Exceptions to
Backward-Edge Protection".

In a nutshell, CHOP is a binary exploit technique which relies on confusing the unwinder when operating on corrupted metadata (e.g., after a stack-based buffer overflow).
This allows an attacker to hijack control-flow even with traditional backwards-edge defenses, such as canaries or shadowstacks, in-place.

For more details, please read our [paper](https://download.vusec.net/papers/chop_ndss23.pdf) or browse this repository!


## Dataset

The crawler for our large-scale data set is located in [analysis](analysis). However, if you want to replicate our work using the same dataset as in our paper, you download our crawled packages directly [here](https://download.vusec.net/dataset/chop_crawled_debian_packages.tar) (~67GB).

Alternatively, you could also directly download a mirror of our database [here](https://download.vusec.net/dataset/chop_pgsql.tar.gz) (~2.9GB) and use the [`pgsql_import.sh`](pgsql_import.sh) script to import it after unpacking. But be warned: this database was created at the beginning of the project and grew over time. As such, it may include outdated fields and tables which are not used by the current analysis scripts.

## Citing
Our paper will be published at the Network and Distributed System Security Symposium 2023. Please use the following bibtex to refer to our work:

```
@inproceedings{duta_chop_2023,
  title = {{Let Me Unwind That For You: Exceptions to Backward-Edge Protection}},
  booktitle = {{Symposium on Network and Distributed System Security (NDSS)}},
  author = {Duta, Victor and Freyer, Fabian and Pagani, Fabio and Muench, Marius and Giuffrida, Cristiano},
  year = {2023}
}
```


## Black Hat Talk
We also presented our findings at BlackHat EU'22. You can find the slides [here](http://i.blackhat.com/EU-22/Wednesday-Briefings/EU-22-Duta-Unwinding-the-Stack-for-fun-and-profit.pdf) and a recording will (likely) be available at a later time.

## Recon Talk
We presented exception handling internals at Recon'22. These internals are useful background for understanding CHOP attacks. You can find the recording [here](https://recon.cx/media-archive/2022/Recon2022_18_The_Mysterious_Life_of_an_Exception.mp4) and the slides [here](https://recon2022-exceptions.github.io/).

