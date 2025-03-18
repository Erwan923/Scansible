# Passive Reconnaissance Techniques

* Reconnaissance passive avec tcpdump
        * `passive-recon.sh -i [target] -t 60`
        * Description: Capture passive du trafic réseau pendant 60 secondes
        * Tags: #passive #discovery #stealth

* Reconnaissance passive avec scan de ports discret
        * `passive-recon.sh -i [target] -t 120 -p`
        * Description: Capture passive avec scan de ports discret
        * Tags: #passive #ports #stealth

* Reconnaissance passive longue durée
        * `passive-recon.sh -i [target] -t 300 -v`
        * Description: Capture passive étendue (5 minutes) avec mode verbeux
        * Tags: #passive #extended #verbose