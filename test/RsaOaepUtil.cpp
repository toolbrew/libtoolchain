 #include "RsaOaepUtil.h"

#include <tc/cli/FormatUtil.h>

#include <tc/crypto/Sha1Generator.h>
#include <tc/crypto/Sha256Generator.h>
#include <tc/crypto/Sha512Generator.h>

void RsaOaepUtil::generateRsaOaepTestVectors_Custom(std::vector<RsaOaepUtil::TestVector>& test_list, size_t key_size, RsaOaepUtil::HashAlgo hash_algo)
{
	std::array<RsaOaepUtil::TestVector, 4> tests;

	// test 0
	tests[0].test_name = "test 1 (small message, raw label)";
	tests[0].label = tc::ByteData((const byte_t*)"This is my label", strlen("This is my label"));
	tests[0].label_is_digested = false;
	tests[0].dec_message = tc::cli::FormatUtil::hexStringToBytes("D1EFB44DD179C3691A74AE3AA46E2DC1");

	// test 1
	tests[1].test_name = "test 2 (larger message, raw label)";
	tests[1].label = tests[0].label;
	tests[1].label_is_digested = tests[0].label_is_digested;
	tests[1].dec_message = tc::cli::FormatUtil::hexStringToBytes("12269A9630054F054E79A9BE10EC27DD4BED6A3435DE2B764BCDEDA173D14C16");

	// test 2
	tests[2].test_name = "test 2 (small message, digested label)";
	tests[2].label = tc::ByteData((const byte_t*)"This is my label", strlen("This is my label"));
	tests[2].label_is_digested = true;
	tests[2].dec_message = tc::cli::FormatUtil::hexStringToBytes("D1EFB44DD179C3691A74AE3AA46E2DC1");

	// test 3
	tests[3].test_name = "test 3 (larger message, digested label)";
	tests[3].label = tests[0].label;
	tests[3].label_is_digested = tests[0].label_is_digested;
	tests[3].dec_message = tc::cli::FormatUtil::hexStringToBytes("12269A9630054F054E79A9BE10EC27DD4BED6A3435DE2B764BCDEDA173D14C16");

	// set keys
	auto modulus = tc::ByteData();
	auto privexp = tc::ByteData();
	switch (key_size)
	{
		case (1024):
			modulus = tc::cli::FormatUtil::hexStringToBytes("A2A451678C1DFDB0A505DEC45FD34815054AEF603D8169B79743D8562D7F197021BBE7C9D07F67590E8B6720A6DB8C04CC52EAB90554F8F5CE903A820F9C50F7C09265DEEB5F2BFD8FC19A0A4BB6CD52129393AE09459BE75A8FCDA7C74D1CAF6506D121AD13B3CC595F0382EF896FA7569C223D330C1B4B0B4ECF4ADE8B18D3");
			privexp = tc::cli::FormatUtil::hexStringToBytes("1E397113501BA6B0740A623A96203A6E059CC65D5930BA87AEA9A20369D30BD425C0B8B36D76AFAB0223EFD7468AD83B70091CABA38D05F3101F0770721C37837731039681CD536307AD3232C753485CCA60FC243E9CB2A388A79F2E8EA6CC13B912BAD042DAE58C72516D0AFDDB73579EBF095874DF2CF33129AB7BEA0121B1");
			break;
		case (2048):
			modulus = tc::cli::FormatUtil::hexStringToBytes("DEBE4D3F6AA0C4B0F7B90FB132FF8ABAA98DE69FBDE58AABF0494E6C7327859A5C3638DA1236B2C23D92175AD1A74C72E30AEB539CC947CBE5ECB080ED45391FFA3DB93227EFF30804660782CF56E740DA584F677D96714823C6B1C31E719A2D479314A1E7A493D72909043580058C3AE8A17187140D0A6B60054435A1CBC01BE7DF0991ABF254F37713BD93F02B9906610809C5BCB88883B91D0ED86BD2C68AF5661FAE8B9DBEB2C3D90AEE85BBA9A350D29E2E6188696ECCB465B2313DEE088F3352C4D94BA91B36F3FFF2F918292A6A1429CD22E5A317B0BE9684A8B25F55CA38F9BAE9A6EA3CB48F618A71547D832C2E9CBAC97D2769010F5CD03526352D");
			privexp = tc::cli::FormatUtil::hexStringToBytes("268F784D05B70E45FAA4B178423565FD599404BC5BC20CA72662726EA8E2CB28C554E7B3ACDA8648C522F0E31A8F65573041F82A51E6B084B669AAC6AF0CC04E6E625818BC3C386D0761E863F763FA85CA26E69C2A6C2C714A2C4022E0B6D6F386C40A1ADB40AD0D5EFFBE184AF0EAED59CF751966D9B9178C986CCE0214054E1CC0801CF5AABDBE1C7DB8CE9B043AE024A18723E3AB7A68F8806993DD6B872A05BC827CC9CD33E77AEDF7B828A635EE9C99A525204FF09EB8F440825C73C072AAC2AE9882E1B29318434CD6B556A2753451173442BD65082DC4CBB9318F5A8B7FF9AF84CB9F030259CF84039F63675574C16A7027828C2C7845E1841DA63B6B");
			break;
		case (4096):
			modulus = tc::cli::FormatUtil::hexStringToBytes("92654BE390E6DA06A826A8CA54760ED3C2D4F424318C4EA4C0741A98EF13B9DAC07F6BFB5FB8F24889B47556FCCF53492BBAC6F4E3BECEC4F906723ECBC36BAEAFB050DE30A393B7AAADAF45CE258CD1859A708DB22642AD0062EF65BCFACA3519516576A877C431417BA19EE7981BA99FE2818DEDD0A8508080AF9E79D88F1B1B90CE61F8B600D9A919B4B7B2083A88CA536CAF67C2C09A2533DEEA647BA9B5EFE8660E086DF20D6EC5AAA2B7A668B9E8E5D276AD5EE697DA95DDE79A8E53CB2B1DC28268D132B413516ACD191423AC76C7EAD37301411382FE5FB68D2096A74F0811148A87FB3C285893032736CBF5901220C7B7BE04A5E215B0F0FF8076059839EED2E492E86BDE7D6E5206A635B67A62CFF261BC686B45C7E02F485CF7BF8800027A830AE1195E3895EBBDA47612B5E42198BAB3CE3E4837FBD4DABAE199390C7BBBCB9420C2E5173AA21597CA3537B9CC5FAFBEE4D72CB232F8796B525F031B6E9F0F9CDBCDFAD839270ABF8935FED7BF53ACF841091F6B53FE545F251F4754CCE3BC0426828F7473607CBE14DACDED705B800FA93389463DAA23FE187329CB13F00849273797EE5D5936C1CB0336A571964897CAAACE540BE2910B0127F6A2B54708329A4465E4780AC0FAFD25CF6C90857ED01A18370B42CB37DEE3D07D2336F16CA537AFF2A3E312178E89ED5850551328E49294A122F2013C50E7BF");
			privexp = tc::cli::FormatUtil::hexStringToBytes("2CE9E40300C13A91C143FF13F81EB244D8A8F1F02ABD63A15B2423C6D8CE81FE3181C654BC54E70C472734BAC7DC29AEB0BA6070E070794A682648A5A8691F9FDBE9E99D89699E17C2C6FF97987BDFBCA6533005E0EAA9191F9DBAD9C9455E05356BCA07C1FEE093C605D29B886D1BCB8A307953DC6AE040B67404AD47AF9F940EFC79BD080B7AAE4C9984DEB8C19A87BE1F23209B625E29CC9121EA6282A81A17ED02667AC29478F78BB062B49A5AD5F2B493C1F245C3D441ED29C3F5208667B6262EB748C629DAA2749FA225F80E4BCAB36201966E83932364BC63AADF9D28DE6FD8A1A730B9ED0669CA4CB4DAB46F75D081FB140DB9AA54F717AE908CCE684913E078F1FC71032C50CE3A4175DC1E7337C6BB1AF998EADB2713A8D6B3AA66ABBF8FDF9C2783A046C782576F60A7AAAB38E25253A9235C9C94FDAB51380A427C9B604F6373744D23D7213CF1ABC561F4914F7EBFE92EA354FDDA251ACC4F55FF55A9A1F2A0D63654F44CD3A0CD9DACE8B93F47EB542EF825590779F191628EC6FCDDCB419FD89CCBA16E1131E15E0AD730446F993AC9AF9283494A53074CC84BD856D47FA8A682A6728B9F1F60EF283DA4533501FA36C276F5E2438A7A675B871DE92E325DA4E5F0CC5795AE36743BDF209F08C47D91F85F0280988267C71FC9B05F5C34BC5BFAADB1B006C5E18DA769CDD6F88CB0AFFAB0F7CC8E027DF6B5");
			break;
		default:
			return;
		
	}
	for (size_t i = 0; i < tests.size(); i++)
	{
		tests[i].key_modulus = modulus;
		tests[i].key_private_exponent = privexp;
	}

	// digest labels if required
	for (size_t i = 0; i < tests.size(); i++)
	{
		if (tests[i].label_is_digested)
		{
			if (hash_algo == SHA1)
			{
				auto hash = tc::ByteData(tc::crypto::Sha1Generator::kHashSize, false);
				tc::crypto::GenerateSha1Hash(hash.data(), tests[i].label.data(), tests[i].label.size());

				tests[i].label = hash;
			}
			else if (hash_algo == SHA256)
			{
				auto hash = tc::ByteData(tc::crypto::Sha256Generator::kHashSize, false);
				tc::crypto::GenerateSha256Hash(hash.data(), tests[i].label.data(), tests[i].label.size());

				tests[i].label = hash;
			}
			else if (hash_algo == SHA512)
			{
				auto hash = tc::ByteData(tc::crypto::Sha512Generator::kHashSize, false);
				tc::crypto::GenerateSha512Hash(hash.data(), tests[i].label.data(), tests[i].label.size());

				tests[i].label = hash;
			}
			else
			{
				// hash not supported
				return;
			}
		}
	
	}

	// add expected results
	if (key_size == 1024 && hash_algo == HashAlgo::SHA1)
	{
		tests[0].enc_seed = tests[2].enc_seed = tc::cli::FormatUtil::hexStringToBytes("18C19B600B3A19FDD8FC3EFD89DCF02A93A38D49");
		tests[0].enc_message = tests[2].enc_message = tc::cli::FormatUtil::hexStringToBytes("7FBB8CA153F44DFF6E69595F1CC3E8F9092B17F44400A1375F074366269FE20601888FED57E2C7C0C441B79853F86D1364DF6A8595F3A6FC9AACEB2AF46B31FB836B9D1679FEF94981338AFEC51D409B0C9B68FB5F3316F46A99C4AF2BA200DD98AC86F8467C7227895ED160D493CAC24B692C2A82AE813F49E218E028B8C126");

		tests[1].enc_seed = tests[3].enc_seed = tc::cli::FormatUtil::hexStringToBytes("C276A7B930AD3D02B43A07288AC01DFE5BDFAAF5");
		tests[1].enc_message = tests[3].enc_message = tc::cli::FormatUtil::hexStringToBytes("0EE0051E3C92FE2D595E1C518B291760DF621E2DBC660833E821947017D4F878152F6752E86D266B3504172B076E0D5FB2830DE3C8B3DAA36B05ED59AF414E453D0B1B688C8BBA68F2F3E9683CA6FFEE8CC85C1886586DA02BF387B9FD646864E7FE10387781A6D3B720A7C74C3DF7290E0EDF76FB7316109587325B95676B85");
	}
	else if (key_size == 1024 && hash_algo == HashAlgo::SHA256)
	{
		tests[0].enc_seed = tests[2].enc_seed = tc::cli::FormatUtil::hexStringToBytes("4379DBF9B508CBD9D2CDFD951907C09084E8C9ABEDBCEA96C60FF1AC1D9B1943");
		tests[0].enc_message = tests[2].enc_message = tc::cli::FormatUtil::hexStringToBytes("12120A3B1F1AB6A72B14B29CB220B9D042358865D423FB221D15698D987A387C015363DA1BCE6852F84987948B07FDBBC89AA87D70441EF8F339FAB5789EE277958445DB49148D6146D582255554C57B31CA9CBE010B54A76EAA7E9FBE67FEEE507198AD069B7B1BFFD487BAF6A66F4A2AF5FF975D55A00B98EFCBE7EF7D215D");

		tests[1].enc_seed = tests[3].enc_seed = tc::cli::FormatUtil::hexStringToBytes("6A8277479CE751792CCF0A8A462416CB0A35D4BFC0C61DB4B81E401FEF006AA1");
		tests[1].enc_message = tests[3].enc_message = tc::cli::FormatUtil::hexStringToBytes("6F8EBA9FFADCB912F9CE2CDD9CD8A9032736B431B631BB2E7F410250B5BFD19D3BB2EA19E89FAE8C0931DC94683FBC8349FF2EF2977550FB0029DC80D1199C3A35C7C04BF1AA8C51F70ADFB3E33FAE25B8FD808EB1D5F561A9FD06A08194A2746F5A24BEC4E925C0DDB2166E0F3E0078CFA0F5C4CE44D1BAAD3A05C85DC44411");
	}
	else if (key_size == 2048 && hash_algo == HashAlgo::SHA1)
	{
		tests[0].enc_seed = tests[2].enc_seed = tc::cli::FormatUtil::hexStringToBytes("8816C0CA54AAC6219B7ADB78A8CF401FA5ED00A0");
		tests[0].enc_message = tests[2].enc_message = tc::cli::FormatUtil::hexStringToBytes("B9C5CB733B672D15B91E182B79DE9A9790177A4CF3BB1EE02E3D983D62C0F602D9045D88F4C18232D340D93A9EFB50E8B3F5814D910D01DC61B07D722DCDD70B556A45DA3E7616E801734FB6C50123AE234AAB4C85730502A488E44724AF52C635D28A0F74374173B3F46F0622F2E1109BFCC1FC47480F1F9400D9EC6A407C3ECB581874578D1E9EAF0996D621E40606EAEE5E5EAC9ADCD2A932FA36C3B6CAA8DCFE6FDD057049927FF5FED90BA503D539085BFA6B743B4DD4E1D00FB0678859B29AD9804857C598946E3DF6DDC418620DE627B786DBDCEC704B7D658E1F1AAD42A0FD971C8F2DBE978D852179E8B687F88C3CCAB173A425757F210979EBA634");

		tests[1].enc_seed = tests[3].enc_seed = tc::cli::FormatUtil::hexStringToBytes("75D8F9CBA4B4BC0C36E203A09C16BFE02368CC89");
		tests[1].enc_message = tests[3].enc_message = tc::cli::FormatUtil::hexStringToBytes("877E2803AD28235772F383BC2A0B508CB6D881C8F0168160D64B435EDD9AD08D2F19E1AE8CCC10FC4112C519D4A40F22599654ABDF8FB1BE178C5C5186AF01A4611554B384B64124699800DF925D9A30331A4DD467D18F6CCF8D5E861604FA1B448894757254873B7AD48C1B5BA0B854368716923C7C67663F5A869D789B3E45ADBDB0EB01676BCC16DC5691C96B2C6BD59BA280F9BCB865E546E833248982A0BAC52ED479BFDBE2BF5F402DF900BA3E6517B00A9728F59121E509C6AF4FBD4EC3A35AA1285C45256D1A2E9433D8FA2F894542C52347A7A14A9E7EA867E0851E51D44B5C79131924F285B8FADE778C56CDBA64C21F0A78B47BEA996BA3C250D4");
	}
	else if (key_size == 2048 && hash_algo == HashAlgo::SHA256)
	{
		tests[0].enc_seed = tests[2].enc_seed = tc::cli::FormatUtil::hexStringToBytes("1933B327491AAD845661C64963A1E91FD820AF6E16D3B07B2965481C0FCF25FF");
		tests[0].enc_message = tests[2].enc_message = tc::cli::FormatUtil::hexStringToBytes("BC6678B5BC8460527C2A86A134C5E8657B4789B3FA4DAE988487907148739A5630F39A3FF8E94FF30331A02272FF2A6A59C3165DC2175BFDF9C77D4B4250FE614030B8AB7F3669CE8BB0A2F63E07CED087382E2C3A73B7A495184D407F7A3BDDF3F682BFE88B1981B0E31EDFB12556B7701BA49B8ACCCF57B48F6184F5255B5B237AD49C2863C70B07734B894A647B0683E187615C41B8AEF51FD0A21ADC4C5FB4FF087DE366C25ECCB9D0437793F4F7180AF9E8F8E9EFEC0E294E433BAD79D36511F876D657C8052DF2FC6182C30C80F9CEE1D9F160EE7850EB90D02DA4BABFEB3EAE272056D6E4424D617E41050259447D3F4A2BB559CB49BBBB509152A920");

		tests[1].enc_seed = tests[3].enc_seed = tc::cli::FormatUtil::hexStringToBytes("1F57E87A75EF286DDF3FC368C06B3022A0B1D70F852F0018E2159A68C25E20D2");
		tests[1].enc_message = tests[3].enc_message = tc::cli::FormatUtil::hexStringToBytes("64593270A26D75F88A13D88AF48E3DAA9342C8F3DBF030E6D3B61B0D20B30F9C33126E3EB3A13A94566897C74BFC2656617081BBFF5E358741FE6EA96A2912C4E5A0428860DF218BE77CAD183E8533226EEE8689289B89AFCCC9746F103567D050234F0060AF679292EE0E36BCF6BFA5F9F594284291991B08ED123E404F7413FD8B61393C5813A865DB1B40C010D240EFE6B0AFE7D2DF96A0DC863C0182605E93C5E6ABE2147B2D4B540B24D3E2993EA48C1D13B08B7E1CA8F14B351E9F0CD8EE31121002107649BBA9C58AD5382837640293A41AB02E835D51408C86C80CE2762054CA0CB005850025499F358E630C0D8394B089BDCFA2AA9103EF112F3C26");
	}
	else if (key_size == 2048 && hash_algo == HashAlgo::SHA512)
	{
		tests[0].enc_seed = tests[2].enc_seed = tc::cli::FormatUtil::hexStringToBytes("D5D1D6980B658CF66E5CC44F0C6CD59461F72D531C3DA02A2874CDEA653630412DC03CABEF601E2F2CC500D2E001539E0F355B534505AF6F1A899AB76849E6E1");
		tests[0].enc_message = tests[2].enc_message = tc::cli::FormatUtil::hexStringToBytes("04234CF8E2BB775CD69734F288B2EC5C3E0E77C9AF2CBEACF1A942FB8FB8703DE4462EA86C749C676646106B8D33D8443A1F3B3B60D771EAC7C28A47B633DB2D8643EA96C3D74E789AE17F52448369A7B62411312A469F22172A3E7E1F24C58D9BCABACD985EA51A9D8C44B36A221101B1FC5BBC64B1B1749912642A42582D1DFDD3C5D2821A4D4C0B9860BF5095AA01C8299CF1466FC761E6FFDD75657A37328A2DE0D6F96398EA26E6ED2853C575B1683CAD9DDA60D008D11A1CED17F7B30428953570D1B40CC3C55A3F4093CD66D5F56BCD39D39C218788AE550DAEC56990E81796608A01A6995E1B7A2FC8B3DE7970676CF2FCEF76E17852F973352A5F22");

		tests[1].enc_seed = tests[3].enc_seed = tc::cli::FormatUtil::hexStringToBytes("9A7689D4F8B664915AFF99C9B267FCC37C09368275AEA44BFA00446142180ABB65011A41D43491CFC2DA939FD211FA5A5B2FCFFE67F40AE11B8EC9836B0CE5BB");
		tests[1].enc_message = tests[3].enc_message = tc::cli::FormatUtil::hexStringToBytes("C0C45218128C97A70A8C966511021CE52447B236EDD0DDE17D711FD8B345E916E1F5D42BB56B86FC662BCF28C11FBA082359A81FE5C0608804E152D9F24C5FA4A86E3B0B23987B548183C16B91411F946B9C6DBB8FC5017E6D8C57F2F2CEA65CB5A71588DCAB1EBD5740A4135ADD276B74D51F57EC64C500FAF81CA22AF809D12B37AD04200BF95249809F36734B5BEC98680C3DB73DF1F4540234E035123420B3F67169B0C12286E23CFF54A7C1B90EC1C3443EA66E6ADF1E0F4BDB7D2C6F7F6668DD8E68D3F714B3ED963643DB61293C0D14C94FC57369BC50CD890EC76B72D1DA628D29CA8588F3727953D29D63BEB9A5A1CFADC24E3D9C1157F0E37CD487");
	}
	else if (key_size == 4096 && hash_algo == HashAlgo::SHA1)
	{
		tests[0].enc_seed = tests[2].enc_seed = tc::cli::FormatUtil::hexStringToBytes("144C65BD99D1660E0DF7F6552EC49A4F511A1324");
		tests[0].enc_message = tests[2].enc_message = tc::cli::FormatUtil::hexStringToBytes("0CAD479D4F74F63398F35D546A0E2D91ACD88DE5F539F5324C8ADBF9DC14FB78C79414FBC7F619277F246239DFA06C889BCD102588452B366B1724E41BE92B2DFB4635200B2C6263815894B91A912E7B7FE8B96858385B6E74F26DBC4ABF96D4A99710881706A3F4CDC9914C9646AEB005A6EC6A996424DBD853BCCF1CDFC96F8A67EC05B64F7C1C30199F9AA6519F0BF9E643153F98A1DC430EBD650FC1F435111DA7120E65F878661C96C2952A635010FC9B0EA2ED1373B0A88FE2FBDC24D28C54A2F30FEF0C064D7FC2D5F5AD1BC4B51CD82CC8B2614FFB3CFAC20176ADD9AD08AC23EF8C478C98D4A36F3715C68920D7424F8552765FFAE28AAEB043B1BB64F1F9C79E4535EB834898F9B71F6FFC3199D2FA3332B671AF8D4489019ED54AF781BA981AEC5131C8F287C8677CF7A9908CC7D56E688018E9B971310D480E32B4966C5FE53AB2AB074AE021EFA46A8D1AD6C2EB4CB50E71150BE14AC6EE61F9B846BCCB236A9B28A9F86C6D29144521D2B9129EEF424E640E7E8CD273F9782DDEEF660242D6768ED480FF17FA529C230DFAD91E272F5E4E0C6A42ACDFB65CCAFFA8E61393DE24F355296941EAE7DBF9869E2D65ED8120CF83C72AEF79CB9BB61581ED26F0029DF80557689114E963690D2AC77D0744754C93C815A81121667C4CC4E09380C0FB9184DEC8266CBDAB7C75BE5EFC2E36F9DEAFB32273438DF5D6");

		tests[1].enc_seed = tests[3].enc_seed = tc::cli::FormatUtil::hexStringToBytes("DD9D35B22A09EA34A759905960AED9F4081FE7F5");
		tests[1].enc_message = tests[3].enc_message = tc::cli::FormatUtil::hexStringToBytes("5308061312A823A1AEE48EF80B64C804C868416F87497D1F5607ADEB3F87F539022CC26AACF630955D11EEAC6F7D84FF46BAC539CA690A90D81162E8870946A62054FB22C25CCBE9BBED517F77C730A08C90893423169E95BCF379AC387AD96B21129FAA93DCFFE3C9915B12340DAB17F5D6FC81664F5438ED06144B93958FCC23FCAEA2F49296B3C1BDDE44FB1CC087B37DBB32323B8FBA0B6D6239743294114C894ED854929C796E48AB8B7DF4E1BD276BADC47803D9339EC12F974D4946326E11567A0A2C107D6453A071A765E179806961FE7BC611792038DC64086E6B9B23CAD997DD46F3D07B27C909F63528F58EA8327C32D7C6FE102E81581B10D5C4783F85F23645F44528A72565BEC696D8077514726321E80681885B4B774F214C98651F39CF9C410F6C0BAA2A72D822F7AA830E52BE11479948E8AFC3159ED5CD55ACB1E5E77F0BC0863BA1F0C4C15E610187265ABA88FEA24BAE1FA5A9C2A062C6CDA7E9D5E1FD05F68722C9D44AA82528AE307DEEDB613A09266E389FE8CB92080B09910DD3A0DA1F9D9846948558D209DA4AF33130BDA311347EE39A11283F1954DA00EC28238FAA8D28383843434F5178BA4CD11190175BCA1B226A2CBA373AF425E9DA594AF9475AB61AA0A7C6B7A059ED3C7DFB4588672E065BE56206B9B30D96BEE387E4CB1B3F8F3CD5AC01E9DE136C10D94BDEC912CD2788AF2EF22F");
	}
	else if (key_size == 4096 && hash_algo == HashAlgo::SHA256)
	{
		tests[0].enc_seed = tests[2].enc_seed = tc::cli::FormatUtil::hexStringToBytes("037DFA32F9D90A0DC9D43CDE371FF816388E3D027ABC6C33C3AD443A0F8DFDCF");
		tests[0].enc_message = tests[2].enc_message = tc::cli::FormatUtil::hexStringToBytes("5C478CB5E30CE0F96E9E98EDC8047A076667B18AEBFCEFA9A8CE6B69D97040DACB796BF12B01BF60E2819BEDE3C8AC6BF419C628BE5BBFE65783FE73C325B9FAF039CF58A444547A2509DC28D48B0A8E6B089614EFE5D13C77BFA74ECC4641BD432EE00A8149EDD8A7E2A3B98110C98B2D89505A4C5F93C2ACC1065DF1C55C7A907715D4CC8BBD9512BE079F82872B7DD56A3AE6D6ACFC751E8FC91986FC83C3452448DF04771293C3F15C57810310C95D6A901E2586A94CB66C9597804751D980561F88DBBA7AD20A0C34CAB9D94A666F2EBAD7B4C7F6A81415ABD5C7277A4313E0BA1CE6977D96A89E0A207E648A26AEEE208CD2000BA927982510521A59E574931431B74D43AEE19A2FD9C01E7B56FFAEB0A7063C776FC10728474827637CFDEB9639913B5CC4930649EE963A379F87818AAFFA96E6AC29B69B3057D55831DDABAFFC080C30997EE9D7F56C554F8D86214B4960DF342128D94B323118BA1F5C6BD472EFCD6A8B1921747BD0345292127B625E3001CFAB0AB000CFEB05593FEE3D59844BF172AD1E16FAD0DAD6612C40E799D32170427C7660AAB3C891A6CC32211DFA6798F372484E3F36AD41C9F000B04C3DAC3550B303B2EC2AB5C9AC4ACDABBF55B3C382F0F318BF9C09203787DBE2EE08CF1DB6F03AE07EED874F2E2BD114B4125BCCAD061A8E5BF6D3557DA6171150214633C0C832BD3C6DFC2985E9");

		tests[1].enc_seed = tests[3].enc_seed = tc::cli::FormatUtil::hexStringToBytes("B4C84542A6E383C520FA1B4E055D69CF0DB174F24011485571E684108EF9BECB");
		tests[1].enc_message = tests[3].enc_message = tc::cli::FormatUtil::hexStringToBytes("530B370F66765E2033AACFE6A114DAC84BD49FABFBBEC4A5202F2C1684693AFA3B145930B46514A03395CB978EA3BC81B89DDB200E223172FC1599E6E80A26C5393C0F04226D2DBB53DD1DC0B2A177C23D3BA7C5EBB0CBED10240FA4F2731BC7ED8696E1BD6CFA7B6FA7AE0BF85DE53EE98EC01805192BAAE933F234DBAF6D11E167C7781283D681CF31A9A0B202F75F06CFB3C7AAF7E8F313B890A3A83AB81FCD88AC09937EF5FBFDA50413DB347D58C425ABFECE21CCB5DB39A7022F2CE2F116B3B343FE32E70876F230F51F9A71C1200F0EA899C3968C19691E8A8322CB8BAEC66F7734AC309543951FBE80662C90D29C53217E78BFA470886570C970CDF1F43088D83DE1100DD0FB068A7C7A8E8CF39F84F11074FB89589B5F0517ED04B19E8651008F265982336D6D9A96CFD03BE909B5671659BADF447537461545156DD3058773D8F6C1840789451CC3419E3D18D199B0180F751BD6D0D9EE3687E467E7E5AB0F43437FB4F5E4CAA2E1DFFE3CEAC60DCD8229F131833CDB41E9B8BBDC517437BBBA43BCF411A69F9C6ADDD8C0386F9FA68009FC6041E8B91EEC00413FEF985CBAB6BB32A579A09170F48DB007A55BE8AACA65617DB3368421C163A9E9E78F561747D4BAAF64A68F3FE52B0061163340B9F007C46561502680874631E8AC2E39E645B732D263262F708A711E680277E0FCF5AEDAAAA25BF982DB4CC24E");
	}
	else if (key_size == 4096 && hash_algo == HashAlgo::SHA512)
	{
		tests[0].enc_seed = tests[2].enc_seed = tc::cli::FormatUtil::hexStringToBytes("A8D827D8E8B0874B956D96C9647E76DF2F761C520EB28A548C651D917AB5A4FB6BC62F825C878F1C97E2FB2FF286DE827179A43302F2B573A64CD740B8AFC51F");
		tests[0].enc_message = tests[2].enc_message = tc::cli::FormatUtil::hexStringToBytes("15D7A37165062CB21246F7A38A5C643C767BB1283BC07A396B6329D950B9FDDF3807590B0B9A42299D3F6C9453A0710D852E9AF99640B23D60BFEBC7DA6F091929D6B78F80DD0B8C676E69F6878501C6A9835077C17B9B3B4C9BB9D99E357B77879B2BBC5FA93F45ACC055F02A1A2777D1237E945EA166C105F3BEE662B967DBE24483CBD8FD118340197431A22682E47B4141E002A7E722B3798EA0C9B176041B9643AB1EAF312BD6946A09E6BC85E813FCF23B87A26BABDF31F88B91F62DFD4E6CDDA44E912CAD400332F24E7438472B39A3C1AF5D0A142ED80777678B3B4E21B8359AB61911075C009D23EF344F2FBFC9C6B5FEFF596F852CAF4BA5F5A28E6AF7349BB59720F7FAD094AD9132600FD761B4B6E3348D992EBB82DD7693D285F769036527152B0242D1F188B3AA1C626385AB7D24AC1667829063E7C84F6BB4E415164B2B45D3DF06F48A77E60D97B366C21C2AC8CABA5847375746AB56E44BC6F7BADCA2CC7AEA4F40F0D990563EE0F0930410E6CE07FC27EECC717141EF201BAE05DE92C8D998D8283E3A5929DCB40BF3226C560F6CD9BCE9EA3E8B45CE3A4A1C21B972335E06CFEA83728BB3D75F1FD848B520F353C992E7B4E4EDA943A24E52BB50B6F346140033ADF0C4B2E580C98380F7D78FA22BCA1FC43140B6DC67B1DC5075E21BF30B1BC9066BF091706BB49028DEBCE9C744AA15079184B97393");

		tests[1].enc_seed = tests[3].enc_seed = tc::cli::FormatUtil::hexStringToBytes("BEA7FA2E2C9E9BDE240B7DDABDC083517E2CD57AFB2FEA999A3958B753D1C777DA278845ADD1EFEC446BD50417D4E9ABEBEDC28362DD7E661BF350D0E3805359");
		tests[1].enc_message = tests[3].enc_message = tc::cli::FormatUtil::hexStringToBytes("558B1A6987E63E9A7FD97EB81F34E52BBB417690B417986CF75AAE18EE3A309B58FA1E4A2F8B1C1A1ED849AEA2F67CA56CD503FB4863B65267F8D6A62E440B0EA800F983D572232ED132539FA43BECF4E903A6795AC7CF462F44D19017D7393B877CA846704D0CCA1F5AF6574673E4DF374F1C572938DC69B9846E1CB066EF2D3820D26BAE89576ED7B21BE33AD27A2A30465823F70DE3D55E0A08D25E60E723C152E7A612CCF8A9A1185530A102AA43174DF3E3D900D559DBF15E4A36360C22B4550A1DE49D7105F64B02069118CB49C460AEF0EC4A063ACDB01FC83CA3F6796FA9DB0E58C435030499E70910512EBC4B73D6608B932C0DB3939476B3E0CDD7EE81B3890F9F2B0F4096A58954143773DFF1E97D27EDA1F53AE42E57FE28013AB8925E060B1B9F12D0E33706F1D3C711910A398EDA1E4D1C4A99DF96C706480C1A653A12D2F488629DDEFD1C3BA4EB6BBEA60E0CB28BCE769066DED683663D754476794A5F3F9D81E10A16CACE1BCAE7439785941868DF656830ECF62D367E46F9BF1C5C3FFC760C8FFD302D55A9E134401B4C55FE08F9509419022F05014CA30D75FCFCA33C882B803C38AC6E0A1CF07D6E9B27D1BAC7C4454D6DE03EFB0A3B46034D45AF9EDB7CC5C0914C04BAB2D252144947DCECAD197FE8BCA15CB0EF5D3A0621AD7824C65144B25759C1B9AFBFA0E808CBF0C613F1D79F3347048506ED");
	}
	else
	{
		// no case for provided key size and hash
		return;
	}
	
	// copy populated tests to output
	for (size_t i = 0; i < tests.size(); i++)
		test_list.push_back(tests[i]);
}