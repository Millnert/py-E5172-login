TESTSTRING = apan bepan cepan
URL = http://homerouter.cpe
webresources = /index.html /css/main.css /js/util.js /js/lib/jquery-1.4.4.js /js/lib/log4javascript_lite.js /js/lib/jquery.qtip.js /js/main.js /js/jsbn.js /js/prng4.js /js/rng.js /js/rsa.js /js/base64.js /js/index.js
jstestfiles = header.js jsbn.js prng4.js rng.js base64.js rsa.js local-test-result.js
localfiles = local-test-result.js result.base64 result.decrypt result.js key.mod key.pem
files = $(localfiles) $(notdir $(webresources))
getweb: $(webresources)

$(webresources): %:
	wget --no-check-certificate -O $(notdir $@) $(URL)$@

cleanweb:
	rm $(notdir $(webresources))

cleanfiles:
	rm $(localfiles)

clean: cleanfiles cleanweb

# as per http://www-cs-students.stanford.edu/~tjw/jsbn/ , interoperability
genkey:
	openssl genrsa -out key.pem

getmodulus:
	openssl rsa -in key.pem -noout -modulus | sed -e 's/^Modulus=//g' > key.mod

insertmodulus:
	$(shell export mod=`cat key.mod`; \
	sed -e "s/MODPLACEHOLDER/$$mod/1" -e "s/PLAINTEXTHOLDER/$(TESTSTRING)/1" local-test-template.js > local-test-result.js)

compile:
	cat ${jstestfiles} > result.js

run:
	rhino -f result.js | fold -w64 > result.base64

decrypt:
	openssl base64 -d -in result.base64 | openssl rsautl -inkey key.pem -decrypt > result.decrypt

test:
	if [ "$(TESTSTRING)" = "`cat result.decrypt`" ];\
	  then echo SUCCESS ;\
	  else echo FAIL;\
	fi

full: getweb genkey getmodulus insertmodulus compile run decrypt test
