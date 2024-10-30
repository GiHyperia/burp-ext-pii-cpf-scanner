import pii_cpf_scanner

def test_validate_cpf_fail():
    cpf_same = [1,1,1,1,1,1,1,1,1,1,1]
    assert pii_cpf_scanner.validate_cpf(cpf_same) == False

    cpf_wrong_digits = [6,2,1,5,2,6,2,9,8,3,1]
    assert pii_cpf_scanner.validate_cpf(cpf_wrong_digits) == False

def test_validate_cpf_pass():
    cpf = [6,2,1,5,2,6,2,9,8,6,8]
    assert pii_cpf_scanner.validate_cpf(cpf) == True

def test_getCpfList():
    body = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. 62152629831 Nulla porta nibh velit, id fringilla lacus 22222222222 convallis in. Fusce consequat sodales ante, ultricies luctus tellus iaculis a. Morbi id eros metus. 62152629868 Etiam nisi lectus, eleifend id tincidunt at, pulvinar at eros. Vivamus sapien est, molestie non ultricies vitae, dapibus a urna. Vivamus tempus ornare sapien iaculis tempor. Phasellus ac bibendum eros. Etiam vulputate nisi nec varius ornare. Aliquam mattis neque non lectus finibus placerat. Praesent ornare tincidunt tempus. 11111111111 huasuhashu"
    assert pii_cpf_scanner.getCpfList(body) == ["11111111111", "22222222222", "62152629831", "62152629868"]

    body = '{"blablabla": "348.192.300-77, "whiskassache": "348.192.300-12", "testeteste": "11111111111", "lalalala": "62152629831"}'
    assert pii_cpf_scanner.getCpfList(body) == ["11111111111", "34819230012", "34819230077", "62152629831"]