function passwordMatch() {
    if (document.getElementById('password').value ==
        document.getElementById('rep_password').value) {
        document.getElementById('submit').disabled = false;
        document.getElementById('match_err').style.display = "none";
    } else {
        document.getElementById('match_err').style.display = "block";
        document.getElementById('submit').disabled = true;
    }
}

document.getElementById('password').addEventListener('keyup', passwordMatch)
document.getElementById('rep_password').addEventListener('keyup', passwordMatch)
document.getElementById('password').addEventListener('keyup', passwordStrength)

function passwordStrength() {
    const password = document.getElementById('password').value;

    const textEncoder = new TextEncoder();
    var entropy = calculateEntropy(textEncoder.encode(password));

    if(entropy < 2.5){
        document.getElementById('strength_err').innerHTML = 'Password strength: weak'
        document.getElementById('strength_err').style.display = "block";
        document.getElementById('strength_err').style.color = "#C0392B";
    }else if(entropy <=3.5){
        document.getElementById('strength_err').innerHTML = 'Password strength: medium'
        document.getElementById('strength_err').style.display = "block";
        document.getElementById('strength_err').style.color = "#F1C40F";
    } else {
        document.getElementById('strength_err').innerHTML = 'Password strength: strong'
        document.getElementById('strength_err').style.display = "block";
        document.getElementById('strength_err').style.color = "#52BE80";
    }
    if(password==''){
        document.getElementById('strength_err').innerHTML = ''
        document.getElementById('strength_err').style.display = "none";
    }  
}

function calculateEntropy(byteArray) {
    let ent = 0.0;
    const size = byteArray.length;

    for (let k = 0; k < 256; k++) {
        const count = byteArray.filter(byte => byte === k).length;
        const prob = count / size;

        if (prob > 0) {
            ent += prob * Math.log2(prob);
        }
    }

    return -ent;
}
