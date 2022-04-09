{# /usr/share/firewall4/templates/zone-fullcone.uc #}
		meta nfproto {{ fw4.nfproto(family) }} fullcone comment "!fw4: Handle {{
		zone.name
}} {{ fw4.nfproto(family, true) }} fullcone NAT {{ direction }} traffic"
