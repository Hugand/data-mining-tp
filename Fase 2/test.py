import pickle

forest = pickle.load(open('model.sav', 'rb'))
attack_encoder = pickle.load(open('attack_encoder.sav', 'rb'))
l7_pn_encoder = pickle.load(open('l7_pn.sav', 'rb'))

print(l7_pn_encoder.get_params())