#include "RsaPkcs1Util.h"

#include <tc/cli/FormatUtil.h>

void RsaPkcs1Util::generateRsaPkcs1TestVectors_Custom(std::vector<RsaPkcs1Util::TestVector>& test_list, size_t key_size, RsaPkcs1Util::HashAlgo hash_algo)
{
	std::array<RsaPkcs1Util::TestVector, 2> tests;

	// test 0
	tests[0].test_name = "test 1";

	// test 1
	tests[1].test_name = "test 2";

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

	if (key_size == 1024 && hash_algo == HashAlgo::SHA1)
	{
		tests[0].message_digest = tc::cli::FormatUtil::hexStringToBytes("0B54234C25D22747C81C7365B04996AB3D96EBEF");
		tests[0].signature = tc::cli::FormatUtil::hexStringToBytes("308D0D22C57A94A1BD04E80081B1B908FFA1ED9255F834DF2A80BB45DABDB796297A18FDE3A5E9B8EDF9A7DED6DDF59A6D038D484368CB90C0A3B96B1FE675FF725F8793C2BA4AEA559E89331924CD8A3ACC6348B0533B1B8A6566780083F9C881E9E3205D5875045FEC4C906C078899E6E31D9BB715760DF779883691583DF2");

		tests[1].message_digest = tc::cli::FormatUtil::hexStringToBytes("62737496A3A99DB6808296117E3CE796201C84B7");
		tests[1].signature = tc::cli::FormatUtil::hexStringToBytes("96DDC708CBEE1CB1EABFCEA4A1A5D7DE8FBE75A84C8C6CE9D11586AEB082B5B95A4FE0CF58712595ACDF45CEC5C6BF4FD680C46A3AB0B4F1B239F0D56AF97F2771490AB43FE6F46513E3EE8F396E6C8A2C32FC307C05C6827C060AE8E52F5B72B609E64B861648A328509E86AC79AD64380BFB2675183CC8CEAD5267724F2B7A");	
	}
	else if (key_size == 1024 && hash_algo == HashAlgo::SHA256)
	{
		tests[0].message_digest = tc::cli::FormatUtil::hexStringToBytes("A2386D7FF4EF41BAD87D62CA8BAA1563AAFDF8013ED6B3668BFC1E7616D86CAC");
		tests[0].signature = tc::cli::FormatUtil::hexStringToBytes("6F00ABCD0C69C4BF0020B6078EC24AF0393D8271ADCABB16B05520F687DC5FE6C56C0090C5D042296608D655471A189254731B5D5193519B5C57CB323008EC2F4158740D1FB3A95DA2EE26483487D070498BB6D1580E11FBE046D750B66C649A7D5BEC483F73249F85D7DA175CE0ECA6BFC09EF9F1C2FA16CF72E062703979D2");

		tests[1].message_digest = tc::cli::FormatUtil::hexStringToBytes("0D9E93AE17D944B14BE6F382A64341AFE7B33BE21774654ECF9FB8D3CE036E86");
		tests[1].signature = tc::cli::FormatUtil::hexStringToBytes("365D0E0A3286DD6FF0E6DF0EE04883D73C618A120B4A2BF6275B1B30FEDD17D7F6F1DFCF97CF3CF459FDB7344646BF81FD71EEB45958AA7FE380EE3891CFC445FBEB59AFA1D9209886DE74E2399D9F3D9E2F80369B9FF56EF88BB23AFE986C421D57413B4B74D0E85DB9D203D62D4CA15CCF50AE6A32B451E0EBDF85CA9EEA74");	
	}
	else if (key_size == 1024 && hash_algo == HashAlgo::SHA512)
	{
		tests[0].message_digest = tc::cli::FormatUtil::hexStringToBytes("1F5E7340F40C9B424E8112451133D56DC4EF2221083C96CDC4669BD4AE328659D4872AB16B4720EAEE67637EED14A637664AA92831DC0DE43AC659BB738FBD99");
		tests[0].signature = tc::cli::FormatUtil::hexStringToBytes("8F5AF83160E8B124712FFE5348853B5349BB54CE37E728A63B93A462E38147EF7EB3CA76DFEFF58C55FEC597F1A37A727705367872CA9FB92072717781052AFC8F110AA90C34049DD9A0FB51AFC6F519FA345C7B97B81A6886BF0D71187FEF049AACCA3F9C38F849C5353F6E4EA8DE84250B03AFA21569EC2A731A82A4224F48");

		tests[1].message_digest = tc::cli::FormatUtil::hexStringToBytes("709BA2DD10CFD1ED5D3B2833B6B42664ED9684DFA239520D842598A75BED777BB7D5D71E7D7A5E5658C925AB96C8ED99CFAE1E46A33C4736655CB3BC3EB23B6B");
		tests[1].signature = tc::cli::FormatUtil::hexStringToBytes("A01D15754D220D55B7597FD233235C425DDF5D141F38A7A4AA2A733788CB366384C3D621DC3BCADEBD85B7556D916D541672255FF634883447D49E84A73F2FE8AC67CD6E95BF3B2F4ED577F96EFBC5071ACF7E7E5F88236C553F3A74E98E2A3CA5CD0748B08E928902253E719A74FEC41A78916536F1144678DC4AC51DB19394");	
	}
	else if (key_size == 2048 && hash_algo == HashAlgo::SHA1)
	{
		tests[0].message_digest = tc::cli::FormatUtil::hexStringToBytes("0B54234C25D22747C81C7365B04996AB3D96EBEF");
		tests[0].signature = tc::cli::FormatUtil::hexStringToBytes("2AA9197BE6C552A0AE8435BDFDA57D53AF126A77ABFE7BA3C3D746BBD1A56ABF83A95D0E827A355B3C9578006442D4A1498E7DFFAC387B8BFB2FD5C265B78F0E325B591AFC8E403EFD679B9665FA6871A8BEF0619062CC37E30BA656D8D63FF3F3BC2F7E52C565EF13017EA2AB7801E31367528714C3B421E260C8CACF7D6FB0A3E0A43BA56C1B4E21708FB2E4E5074B214B918B36BCCD9EB3E8E246CBC6DB3DF0CFBF24D29EA79FF77EB7B50700D02AD81C3D45E222B5C7189B9AC6028182C57C7519BA2BE360EBC1B5BF9654B40A0357B47F8DCA967339E0D8C426200A6F5CEADA3A484C9E9FFCDB7C3558214E3732835A4ACD40558942AA1F83F0FA62E7E7");

		tests[1].message_digest = tc::cli::FormatUtil::hexStringToBytes("62737496A3A99DB6808296117E3CE796201C84B7");
		tests[1].signature = tc::cli::FormatUtil::hexStringToBytes("A4D943211BCF11B6B900043D699DAB1391343C39B41369D4F103B0C5174A1CD4DD42D78CA5A9237EA8C8AAB4B26E6434F414AECFDF1FCB047B105096132F786023359FF1423C5F87AF6E2B513F3B8AF2FFE12AA5ED1999BB0C953C3EF2608A347676F76097092ADC59B3117C67D14AC7ECC5BCFA4587A6D651CE8AD0DCACF990727E32A3D2DBED1E52C6D5D96AA97276C2020B0C0928D3EE3E7D7E285BEDF781BD878B8468447E9C5DC0343837B5A1B83FBCB6747F536D41CFA6718162392F557BC5224357C170EA384502BC608F33EF9F5DFE42B12652F132C4C28142184D10B3D5CFAA43FAB01B63A761A571630BCBF8CD439AF11CD83EAE416D4892AB2640");	
	}
	else if (key_size == 2048 && hash_algo == HashAlgo::SHA256)
	{
		tests[0].message_digest = tc::cli::FormatUtil::hexStringToBytes("A2386D7FF4EF41BAD87D62CA8BAA1563AAFDF8013ED6B3668BFC1E7616D86CAC");
		tests[0].signature = tc::cli::FormatUtil::hexStringToBytes("460AA83AABDCD786A4C20DFA4822E4BAAD19B1B51B51595789483A4597819A8DD7AD78F2C4587F8881A3F507A32C4E421420361FCEB617313092506C084C12153683073F637BA1517D52F157178C8CE8161C73DC017FE03282F170E5B6DABF2E5B58D7C5603786165B3889B103C9C1EB66D91EFD9B6A1708BFBE1B5D4BF5CE2EF0DDFE3AF1B52B4A120D9E89A15623E1E579A562F9FA342D41BB25F438BF4934C3DE592A79A3E0ABA0A181B6C402C10E0395CEA8D68D16CB916A66F18D16D7C3534E95D97E2501CE232A1FCAF4C09D8E7314A0E80C8D5867469F2730C894909197EDB3EA5D701160305CF6B335EDE647797C9278BB5D15CF8B48905FB469750F");

		tests[1].message_digest = tc::cli::FormatUtil::hexStringToBytes("0D9E93AE17D944B14BE6F382A64341AFE7B33BE21774654ECF9FB8D3CE036E86");
		tests[1].signature = tc::cli::FormatUtil::hexStringToBytes("76EAD23F3FA6392A8301B3AC8DD4DC28046BB4FD67E2FB53C00CE689202D67CE38BF64FFF9771EBEB306F4CF679FFFD6CCE39CE4252D827A965C2EAB6A44848AAB087535BD46858AF516632F8D82F8E98125BC59971369855490264226F286436746DFAEF3843710189E47AA95E478F626BF11E26A61BDAF726B5F44106EE290BA5A5551063623B276D504D5F391591303735BE8C5570E03A3A60FEE9816436AB99A3232A946E58E2CBC46887B5C382FFC00F09FC5FDEE8F27A0575F36F9146156FDF322359B06BFC5859585E978EE01508054557B2D2A213E53C813519B707A9D832A50B576D5918BA80C266A1FF4A88E6712835F9E74DF9E5B906E2B2249BE");	
	}
	else if (key_size == 2048 && hash_algo == HashAlgo::SHA512)
	{
		tests[0].message_digest = tc::cli::FormatUtil::hexStringToBytes("1F5E7340F40C9B424E8112451133D56DC4EF2221083C96CDC4669BD4AE328659D4872AB16B4720EAEE67637EED14A637664AA92831DC0DE43AC659BB738FBD99");
		tests[0].signature = tc::cli::FormatUtil::hexStringToBytes("916B2800B5E76111A2F12A935789CA36B1B5313BA0C0222355F5DC328C609930B6643DD3518C74DDFB5DD9720AA1762664EA82FD393A0DCFA80AF1757D4EDA56CCC0342E6A2878EA6D5502F34719D5371D9E297529DF4770A899B11B687342C8F213B89980247A724CD14489FF1BD627DD30614CEF8F733460AFB82EB1FC6FF9B256129C79B7313D015F1F414EE56CDB566AB54B7F769EA8C90D894D773E07073243DDED1E9FA64D1965B9C4F0AF815158FA85DA19BD35CE1FAE654A669B39E99853F4F2F15DB70949055F48320AA00838CB541A27E7871FFCBE449D4E64160BE0F6C48193997F1EEFAE0E62D978965B4460135DFBEBE692FA643764CD8F8E27");

		tests[1].message_digest = tc::cli::FormatUtil::hexStringToBytes("709BA2DD10CFD1ED5D3B2833B6B42664ED9684DFA239520D842598A75BED777BB7D5D71E7D7A5E5658C925AB96C8ED99CFAE1E46A33C4736655CB3BC3EB23B6B");
		tests[1].signature = tc::cli::FormatUtil::hexStringToBytes("BE89EDCE1642A8470F14D27B418BB4CFD3284129A42B596DFB05DFDC5F99FF2572C40513B19019B01D34465A22DEA89952D138C99E588ABEDDC2E4211F944CBEF7A9546541DAD747AA7E0024C8AB9E620D570383145D3BFE4D622AA8D6670E51B314DAE52BCFD1A8BF1F93FE8909318C7D1491E9013AAE223243248AA4DCCFA0DDCB6A6F9AABDC74F2395B666C85398628006D2CFC737DC1D566C6155FD6F84558FC543BBFA1256F8F91E0E69C5BD7C91619DA522F9A5E14A00E42981526D09B9FBFCECED41AC7023C7AA04E7942F67E446D35FD63F5A70D9C8CF30BD01ECAF5C311EBDD1A1B06BCA3C4261E8EB06E9583E18F5359683292D2ACB018E0082F61");	
	}
	else if (key_size == 4096 && hash_algo == HashAlgo::SHA1)
	{
		tests[0].message_digest = tc::cli::FormatUtil::hexStringToBytes("0B54234C25D22747C81C7365B04996AB3D96EBEF");
		tests[0].signature = tc::cli::FormatUtil::hexStringToBytes("226D22515C2AD353AD9B44B20807FBDC18CCB36562FB18A3EE5FB83DC6060697913A06F8A26F8B262AB41E901F69D55B9F22FAE9CF94CA0A7CCB3FC93F36E564223DE09ABA33E1B069C10F26CD866DAF333376E680AF79DF470E5C3CC5ED640EF14279F8D044418126211D1FE26D1418743B549E1E9C74114BF20112B975668FCFC65771B84D604AB0C579DA70BF22522EACD831E1C1D85435FF811478FE95D6BE21E6D0A06E52756BDFA8AEC17D101E1B6FC72FF53E99F1FDD81050509C24DF36D850AAACB555AC43064F3A2424729E90001F29D83F9718A1E4914F9E88C47C2F14038A373251F810D34E504024DD86D44733B94F76D611B921C7B40F40610D0DCAB144CC3775D8D954658530894B925F12E80A5452E6D3FEEEB6F5FD607768D31CAC837A075AB31FBE2D185C36FEBA09C25016315FE8037C7B9A9B46FCB53593C64186690E1A38F6CD7D79D998EA54D372B74DBB0D28F60A23431A4162B38120E799BA0E1D92775FDA9B086F00266F7FB21318B8F8598BF1EF15B2BC21A27C5D2964501C0EED94883CAA842CB653467978560E5F46F3EE2F66F4F0680E0D9E220E532090F100785FB83D13EEA4D8041326C853C60489BD795F2E7AD22DDB01A0E6680DCD90FB76964E9B1D98B92C26B355C194C85A29D1BEC8C31321602C4CD2D4058530C8BEDD1B3D76EADF3379F4C70BD1B48607DED271EF11C970642F7F");

		tests[1].message_digest = tc::cli::FormatUtil::hexStringToBytes("62737496A3A99DB6808296117E3CE796201C84B7");
		tests[1].signature = tc::cli::FormatUtil::hexStringToBytes("5C525B4BDCDDDFE7A7FB890B80A4AAEC1E633C398B1BFE468908453F53E9B81381D0F5E52BD5C17158BEAFDB43672D3DF993847947CE42F3EF8BC72F38A57139F2F8FBB905E26AE6DD848A6C3BFEC35312C64D514ABCB3E28F811ECF5BE8BE8CF62A922B4A2D6D199AA6A3063B6E7DCCE4043840EDABBED252B2DF3644C7AC25E49481F44240F2001271E80ED77682EDCACE9372D144D66A149877DEC969F5A1E02872580B6265ED3ED9F015862805486739FE0162871D4EBEAE10D61A79C1FDB3C5521CA057994CC2444934E24B2232C67B6A3DCEAD846448E14BFAEED7B8F4914F27E1334953746C0AC18EB7CC4577E07B783629C9BD3F10ED91AC895196149DBAD7558EC5229D6BE4D6C5B9B0B8FBAF7E8A57563FBB8567A4E62B212401DC2757F5AAC08EA59924E8C2D475C4B26E8359C8B520315DD31053BF11DD46B1CF3F5F803F8209880D49740A2ADA07452DA58E088D353965206B6F1E429B0E3BBEEF1DF2CA08EFDBC9A84B805F1855608B4724247E0084060A99EDB9EB5FA85471E253E5DCDF83F761AE9597FB6C47B72FBC9EB78C6306B983FE3DC02566059A3784AF222891AEDBF11E906CC6AB7F72E6E194F4393BDF3D76B8674E522844FEB750C629A3BFA2E15D92C2C58B43925C28E70199CB0745C4BEFF0D6EC18A8CB15B740A61B65EE1D8B2204D176AB1A01BCA50F535E8230B742725DA19FC59FF5EE0");	
	}
	else if (key_size == 4096 && hash_algo == HashAlgo::SHA256)
	{
		tests[0].message_digest = tc::cli::FormatUtil::hexStringToBytes("A2386D7FF4EF41BAD87D62CA8BAA1563AAFDF8013ED6B3668BFC1E7616D86CAC");
		tests[0].signature = tc::cli::FormatUtil::hexStringToBytes("29E3EF33332E80A21255159572A6BC3A85037B2FD471E5A259DE625FF8286523974B3FA170D23D54EE5E28FF26FCACB95EF6BF1682EECF1D298C55561A8B7D6DD51D0492E80E0F11C7FE3874049B8DDB6969387752465EE4CF988F709CB8E29CB2DED29BEA6F47D92C15AD7C01127217E34FF252753CABD1392D0FD4C6E55109CE512BEEB459EEC4E6BB69A5CA46B1C2B5691169408EB5C9E939D458371E674FD7C57E10042E01F283C4B63B7DCEAED1E5FAB696A2E24D5D5C3FA2885CCC456A93D4018EDCD0383B0B6EA6D5E047C200EB27535439B869EF925BF0D2396DE54D32E17492A8576519878E417EC09518428049072DC623CCD9B78EEC42BEFA9CE9B18DDD6AD3E0429D791B00588DA25327942FE9AD26C83B9699B161270B0927629716087F13D15D5FE56FAF8D615BC27403D8C3C8C2C1F2751074181D55556AE1D2B38E80589541B7CFE70B1B8B8261A9FC4BF6BD7CE0CA174F972959A24FFD07A6CDF2C2D80C7C128CFF722967DAF1F2A2D29596B92F56D2C65EB1A40E5DED0A8C78ACCEFE52133D08EF8FDC9E6600D67983B29059AEEB76B3449D7A099C2DEBD161F61A80F6F3B6DA8FF569A7C3990FA037BF222480F3727345AAB268C3B0D77BEABD2A8426FAE5B630C577B79586B5CFA3FBD9C4BACA9E5B22846C9A6DBCFA21C3EEC162420DF28184C2234A930FAE41B5B2718CE9C8F89F5F02ECF2FCC61E");

		tests[1].message_digest = tc::cli::FormatUtil::hexStringToBytes("0D9E93AE17D944B14BE6F382A64341AFE7B33BE21774654ECF9FB8D3CE036E86");
		tests[1].signature = tc::cli::FormatUtil::hexStringToBytes("6240DA2CD63671FC6C1E78E6BB5225CC27798B456A5082FE8E8F832CF8934E90F8CA83A03159589589943B9CF2BA46CE8B5509FDB9A3FB28B884D9A5358490CF3D52765F3E398366F768EBB9178E4B99C7A8D194D98CB4E502CBF28657D0E2D1DA26B80CDDFC8B9A7CAC7D51A9A97CA4B39C5464F0A073FE06431E21B1FD496BBC62D7B18DA03284AAB56FCFBD37ECBF8B86CD2C9C1670A1682CF6A448DB02B2941E9CF212219AE0DCF325E333A2F9895B686D61E192973BFEE96CB7876CA542EFED0FE9E5F2B2680822E0E4B72243EF19615EB50D7E7C66992924F15D44B8869776B1D397A104EEDC67B8C6E4F11576430861614B4658C5A4FE853D19B79EAEE18105C6583EF4CFBCE54260F0C8FDCBD2BE71DBE1126C63433741294A844D9FE39BF2189BD7DE4000073F1B3A98FD2215A49E4768A3384CBD589B01E3AD790C6CEE4462A36AA98E5ED03807021E63A841ADF159FCC4CCDA3CD19CFA21CBE5B73A81C8F1EF70E49D3D4807F5A80847ADFD86EA0D7B4699D25CDB5300EA241C6C2AEF2B7BA4A3B02A2C21FBDA0EA8D052CC8ACE8856312B443E86E913C1474D83AB3FF6CC7AB5F8137B4B710943741715634A3E85693636570E13D8433A292281AE0B29ADFE16FA6347CB1AE7F30047B4A95C7BDBB1CB3B4A599A41162E932EEC261B3E022FAA9E554BE84156721C009C987BC6982807DFA97DD7E1E7E1F1B1FC");	
	}
	else if (key_size == 4096 && hash_algo == HashAlgo::SHA512)
	{
		tests[0].message_digest = tc::cli::FormatUtil::hexStringToBytes("1F5E7340F40C9B424E8112451133D56DC4EF2221083C96CDC4669BD4AE328659D4872AB16B4720EAEE67637EED14A637664AA92831DC0DE43AC659BB738FBD99");
		tests[0].signature = tc::cli::FormatUtil::hexStringToBytes("0264109A40938A354BD4D7BCB81FA4ADCCF4DFCDF575F6D30A9EA6A9361C5EBD0A5B9F51E553B9663629113A4E46A907A8A9C03C4A3AA6D4921E879F48D9E02D03AD5FA9F94411EE0BF5568317ECB008C6CCCAAF75B7C8F06A98E0F19BED2178A82263A2DB2BF37FBB8A539246B58686A27FEB0F77619A00B6C49739BFE00901D140CE49218C6B24803A9923C86971E516595901690572E29D4CC10E7D7D72A2726F41C116C3916DA41051C69315CD0EEA8A15F811762EBEE2EEC410D57BE31850C8B6C27C8ED8A768CA89A4DF44FD644D25C1789A5D339CD59397F3EA3464271737AB5E2A6BE47F4C2A8AADB298D8472566335ABD8BF093C72F059E2AFE2D5076ED0B26F935EA910C07D6B6050F0F4D19E3F9F300445EAB5BB264FF51CFF219C78F102E182D261227C280DCEAC646D55ED0C0EBFBF2F63091E3E5DE476BEB27F107B697A7EC9D01CF242A6465AEA164A073727D2BDCEA2D0889E6C547491A036AF7E095FF74E6F267E3533DE0131B391CD0985C095493CE7BC7A69D2D27201D078E0C4041D345A699E1E047B0CF3FED6AAC6CC58EA64752DF2AA6F5325CC3B5D9A9DB337E118B397EDE56EB0B922D6B980D48A63D3AD596AE9F496A3DAD44428E4CAEA3C818DBF672AE6FF72D27621C3600BA41926C9680BB1AA8A9524BCCDAEBDF90B5C094F92393590795F81AB40A5449A64B59BE3C372F738AE8795F3687");

		tests[1].message_digest = tc::cli::FormatUtil::hexStringToBytes("709BA2DD10CFD1ED5D3B2833B6B42664ED9684DFA239520D842598A75BED777BB7D5D71E7D7A5E5658C925AB96C8ED99CFAE1E46A33C4736655CB3BC3EB23B6B");
		tests[1].signature = tc::cli::FormatUtil::hexStringToBytes("2023C38CCB2F4C29342321ADCC88E6C2DC2E5B1BF3BB1451FCAD87D3D2891C01FB14E412DA3E9064F33321DB0CD72C222060CAF65D99E0CC9C7A2E3431896EA07C0FFEC73928E1213A8828BBAFEB50F2E89B469C17BCB021CED7DE4FB556201D00EB8A30B6E6874EDACC9239EFFB06961126B22D4E598BCC712F99A49E1EF010C1D1762C77BFE911F7CF74279A5C1DB183C82F5673C264D388322E0B3F176F65F875956560FBBD7B293638661FE2E7DF26351D55CD64BC58853D33A712B6A9AE810C24CCF5DE1F86FE2636B22AC1A035A8B129A61B5AD962F7A90D5CFDE669497EE0CA4D1762A7278BB34286982BE170E595D05DACBC18FD0CEED89FAF30EFBBAE164456E310AA0A9E4A4D46A3E6643A06F38848C3D57B31F94E8B9832783010B1845469756C8A1C84B0A05A06A2B202C94EDCA4A4B20B019D070274C286268AFD56F14E195A3A437CF6B4677853CFC16DC4CDAEBE9389ED03E55750B1547700552C8D45A0BEBA2BDC4DB1DD5D308F94EDB40E8735BF57018285D54F9CF7D3D2BF9C915CDDD5A6BE3867F82597ACE6881EEA1ED4D68C806497D622261ED5E35B2D21067A5DE25FCA8437E265B57BBB10D03C9E49B5E5CC9EA81418C92AD1395F051FD1939499DB617B21587D6976255A178B98674AC565CAA99C775B002B6361985B3A4C302EB875494F9C1C9FC4D60932B1279B31F58D78A633F69561810DAB");	
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