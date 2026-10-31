"""Word lists used by the name detector.

These exist to keep a capitalised-word-sequence heuristic from eating the parts
of a health or finance document that carry the meaning. "Complete Blood Count"
and "Emergency Department" are capitalised multi-word sequences too.
"""

from __future__ import annotations

#: Capitalised terms that appear in reports and are never a person's name.
NON_NAME_TERMS: frozenset[str] = frozenset(
    w.lower()
    for w in """
    Complete Blood Count Comprehensive Metabolic Panel Basic Lipid Profile
    Hemoglobin Hematocrit Platelet Glucose Creatinine Sodium Potassium Chloride
    Bilirubin Albumin Calcium Cholesterol Triglycerides Thyroid Stimulating
    Hormone Vitamin Insulin Urinalysis Culture Sensitivity Biopsy Pathology
    Radiology Cardiology Oncology Neurology Pediatrics Obstetrics Gynecology
    Orthopedics Dermatology Psychiatry Anesthesiology Emergency Department
    Intensive Care Unit Operating Room Discharge Summary Progress Note History
    Physical Examination Chief Complaint Present Illness Past Medical Surgical
    Family Social Review Systems Assessment Plan Impression Findings Diagnosis
    Prognosis Medication Allergies Immunization Vital Signs Blood Pressure Heart
    Rate Respiratory Temperature Oxygen Saturation Body Mass Index Chest Ray
    Computed Tomography Magnetic Resonance Imaging Ultrasound Electrocardiogram
    Echocardiogram Colonoscopy Endoscopy Mammogram Normal Abnormal Negative
    Positive Within Reference Range Critical High Low Stable Improved Worsened
    Diabetes Mellitus Hypertension Hyperlipidemia Asthma Chronic Obstructive
    Pulmonary Disease Coronary Artery Myocardial Infarction Stroke Cancer
    Carcinoma Anemia Infection Pneumonia Fracture Arthritis Migraine Depression
    Anxiety Obesity Thyroiditis Nephropathy Retinopathy Neuropathy Statement
    Account Summary Balance Transaction History Deposit Withdrawal Transfer
    Payment Purchase Refund Interest Principal Maturity Dividend Portfolio
    Holdings Equity Mutual Fund Exchange Traded Bond Treasury Certificate Deposit
    Savings Checking Current Credit Debit Overdraft Fee Charge Annual Percentage
    Yield Available Opening Closing Beginning Ending Statement Period Posted
    Pending Merchant Category Description Amount Date Total Subtotal Grand Invoice
    Receipt Reference Confirmation Authorization Bank Branch Sort Code Wire
    Domestic International Federal Reserve Internal Revenue Service Social
    Security Administration Department Health Human Services Centers Medicare
    Medicaid Services Food Drug Administration Monday Tuesday Wednesday Thursday
    Friday Saturday Sunday January February March April May June July August
    September October November December North South East West Street Avenue Road
    Boulevard Suite Floor Unit Laboratory Hospital Clinic Medical Center Health
    System Associates Group Limited Incorporated Corporation Company Partners
    Holdings Trust Insurance Patient Provider Physician Doctor Nurse Practitioner
    Specialist Attending Resident Technician Pharmacist Signature Signed Printed
    Authorized Confidential Notice Disclaimer Page Continued Report Result Test
    Specimen Collected Received Reported Ordered Performing Referring Interpreted
    Sheet Trade Generated Computer Original Duplicate Copy Tax Invoice Receipt
    Government India Income Permanent Signature Authorised Customer Code Address
    Nominee Joint Holder Status Active Closed Details Particulars Narration
    Cheque Chq Ref Upi Neft Imps Rtgs Atm Pos Nach Ecs Emi Limited Ltd Pvt
    Private Llp Solutions Technologies Enterprises Industries Traders
    Registration Certificate Application Form Office Mobile Email Phone
    """.split()
)

#: Honorifics that make the following capitalised tokens a name with near-certainty.
TITLES: tuple[str, ...] = (
    "Dr", "Doctor", "Mr", "Mrs", "Ms", "Miss", "Mx", "Prof", "Professor",
    "Rev", "Hon", "Sir", "Dame", "Capt", "Sgt", "Lt", "Col", "Gen",
    "Shri", "Smt", "Sri", "Kum",
)

#: Suffixes and credentials that trail a real name.
SUFFIXES: tuple[str, ...] = (
    "Jr", "Sr", "II", "III", "IV", "MD", "DO", "PhD", "MBBS", "MS", "RN", "NP",
    "PA", "DDS", "DMD", "PharmD", "CPA", "CFA", "Esq", "FACP", "FACS",
)

#: Field labels whose value is a person's name.
NAME_LABELS: tuple[str, ...] = (
    "patient name", "patient", "name", "full name", "legal name", "member name",
    "subscriber name", "insured", "beneficiary", "account holder", "accountholder",
    "holder name", "customer name", "customer", "client", "cardholder",
    "guarantor", "policy holder", "policyholder", "next of kin", "emergency contact",
    "guardian", "spouse", "father", "mother", "referring physician",
    "ordering physician", "attending physician", "attending", "physician",
    "provider", "prescriber", "doctor", "surgeon", "radiologist", "pathologist",
    "technologist", "nurse", "signed by", "authorised by", "authorized by",
    "prepared by", "reviewed by", "interpreted by", "collected by", "applicant",
    "employee", "employee name", "payee", "payer", "borrower", "co-borrower",
    "nominee", "dependent", "contact",
    # Shapes common on Indian forms, bank statements and ID cards.
    "father's name", "fathers name", "father name", "mother's name",
    "mothers name", "husband's name", "spouse name", "guardian name",
    "nominee name", "account name", "a/c name", "name of account holder",
    "account holder name", "beneficiary name", "payee name", "insured name",
    "holder's name", "card holder", "applicant name", "candidate name",
    "student name", "consumer name", "subscriber", "proposer", "depositor",
)

#: A deliberately small anchor list of common given names. It buys recall on
#: unlabelled names without pretending to be a census: anything it misses is
#: still caught by the label, title and signature patterns, and by an optional
#: NER backend.
GIVEN_NAMES: frozenset[str] = frozenset(
    w.lower()
    for w in """
    James Robert John Michael David William Richard Joseph Thomas Christopher
    Charles Daniel Matthew Anthony Mark Donald Steven Andrew Paul Joshua Kenneth
    Kevin Brian George Timothy Ronald Edward Jason Jeffrey Ryan Jacob Gary
    Nicholas Eric Jonathan Stephen Larry Justin Scott Brandon Benjamin Samuel
    Gregory Alexander Patrick Frank Raymond Jack Dennis Jerry Tyler Aaron Jose
    Adam Nathan Henry Zachary Douglas Peter Kyle Noah Ethan Jeremy Walter
    Christian Keith Roger Terry Austin Sean Gerald Carl Harold Dylan Arthur
    Lawrence Jordan Jesse Bryan Billy Bruce Gabriel Joe Logan Alan Juan Albert
    Willie Elijah Wayne Randy Vincent Mason Roy Ralph Bobby Russell Bradley Philip
    Eugene Mary Patricia Jennifer Linda Elizabeth Barbara Susan Jessica Sarah
    Karen Lisa Nancy Betty Margaret Sandra Ashley Kimberly Emily Donna Michelle
    Carol Amanda Dorothy Melissa Deborah Stephanie Rebecca Sharon Laura Cynthia
    Kathleen Amy Angela Shirley Anna Brenda Pamela Emma Nicole Helen Samantha
    Katherine Christine Debra Rachel Carolyn Janet Catherine Maria Heather Diane
    Ruth Julie Olivia Joyce Virginia Victoria Kelly Lauren Christina Joan Evelyn
    Judith Megan Andrea Cheryl Hannah Jacqueline Martha Gloria Teresa Ann Sara
    Madison Frances Kathryn Janice Jean Abigail Alice Julia Judy Sophia Grace
    Denise Amber Doris Marilyn Danielle Beverly Isabella Theresa Diana Natalie
    Brittany Charlotte Marie Kayla Alexis Lori Aarav Aditya Akash Amit Anand Anil
    Ankit Arjun Arun Ashok Deepak Dinesh Gaurav Harish Karan Kiran Krishna Kumar
    Manish Manoj Mohan Naveen Nikhil Nitin Pankaj Pradeep Prakash Pranav Praveen
    Rahul Rajesh Rajiv Rakesh Ram Ramesh Ravi Rohit Sachin Sandeep Sanjay Santosh
    Saurabh Shyam Siddharth Sunil Suresh Vijay Vikas Vikram Vinay Vinod Vishal
    Vivek Yash Aditi Ananya Anita Anjali Aparna Asha Bhavana Deepa Divya Gayatri
    Geeta Isha Jyoti Kavita Lakshmi Madhuri Meena Meera Neha Nisha Pooja Prerna
    Priya Radha Rekha Riya Sangeeta Sanjana Saraswati Seema Shalini Shreya Shruti
    Sita Smita Sneha Sonia Sunita Swati Tanvi Usha Vandana Varsha Vidya Sarika
    Mohammed Muhammad Ahmed Ali Hassan Hussain Fatima Aisha Zara Omar Yusuf
    Ibrahim Khalid Tariq Imran Salman Farhan Ayesha Sana Nadia Rania Layla Wei Li
    Ming Chen Jing Yan Hui Xin Feng Lei Jun Hong Ling Ying Mei Fang Hiroshi
    Takeshi Kenji Yuki Sakura Haruto Riku Sota Aoi Hana Kim Park Lee Choi Jung
    Minho Jiwoo Seoyeon Hyunwoo Jisoo Carlos Luis Miguel Jorge Pedro Fernando
    Ricardo Alejandro Diego Javier Ana Sofia Isabel Carmen Rosa Elena Lucia
    Valentina Camila Gabriela Hans Klaus Jurgen Stefan Andreas Wolfgang Ingrid
    Petra Sabine Ursula Pierre Jacques Michel Philippe Laurent Sophie Claire
    Nathalie Isabelle Giovanni Marco Luca Matteo Francesca Giulia Chiara
    Alessandro Antonio Ivan Dmitri Sergei Vladimir Natasha Olga Svetlana Anastasia
    Ekaterina Chidi Ngozi Kwame Kofi Amara Zuri Thabo Nomsa Sipho Ayo Adeola Femi
    Jane Anne Annie Bella Beth Ellen Eve Fiona Hazel Ivy Kate Katie Leah Lily Lucy
    Maya Molly Nora Paige Rose Ruby Tess Wendy Zoe Blake Brett Cody Cole Craig
    Derek Drew Evan Glenn Hugh Ian Isaac Jared Levi Liam Luke Marcus Mario Neil
    Oscar Owen Reid Ross Seth Shane Todd Travis Trevor Troy Wade Zane Aurelio
    Mateo Rafael Emilio Salvatore
    """.split()
)


#: Relationship words that introduce a person's name in narrative notes.
RELATIONSHIPS: tuple[str, ...] = (
    "daughter", "son", "wife", "husband", "spouse", "partner", "fiancee",
    "fiance", "mother", "father", "mom", "dad", "sister", "brother",
    "grandmother", "grandfather", "granddaughter", "grandson", "grandchild",
    "aunt", "uncle", "niece", "nephew", "cousin", "stepson", "stepdaughter",
    "stepmother", "stepfather", "guardian", "caregiver", "caretaker",
    "neighbour", "neighbor", "roommate", "widow", "widower", "next of kin",
    "power of attorney", "executor", "trustee", "co-signer", "cosigner",
    "accompanied by", "brought in by", "reported by", "spoke with",
    # "son of", "daughter of", "wife of", "care of" -- printed on nearly every
    # Indian identity document and address.
    "s/o", "d/o", "w/o", "c/o", "son of", "daughter of", "wife of", "care of",
)


#: Surnames, used only to *generate* surrogates -- never to detect. Detection by
#: surname list would be hopeless (there are millions of them) and would fire on
#: ordinary words; generation only needs a pool that reads as plausible.
SURNAMES: tuple[str, ...] = tuple(
    """
    Abbott Alvarez Bennett Brooks Callahan Carver Chandler Chapman Delgado
    Donnelly Ellison Farrell Fitzgerald Fleming Gallagher Garrison Halloran
    Hartley Hawkins Ibarra Ingram Jennings Kaminski Keller Lambert Langley
    Lockhart Maddox Marsden Mercer Norton Oakley Pemberton Prescott Quintero
    Ramsey Redfern Sackville Salinas Sinclair Stratton Sutherland Thornton
    Underwood Valdez Vaughan Wheeler Whitmore Yates Ziegler Ashford Blackwood
    Carmichael Dunmore Everly Fairbanks Grantham Holloway Irvine Kingsley
    Larkin Merriweather Nightingale Ormsby Pendleton Radcliffe Stanhope
    Deshmukh Kulkarni Chatterjee Mukherjee Bhattacharya Venkatesan Raghavan
    Srinivasan Padmanabhan Balakrishnan Ranganathan Subramanian Chakraborty
    Nakamura Yamashita Kobayashi Matsumoto Watanabe Fujiwara Okonkwo Adeyemi
    Nwachukwu Oyelaran Haddad Mansour Nasrallah Farouk Zielinski Nowakowski
    """.split()
)
