# Adapted from cycle200's independent synthetic Bash oracle, 2026-10-01.
# The byte expectations precede decoding. Only these generated sources execute.
from pathlib import Path
import hashlib, json, os, secrets, subprocess, sys, resource
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)
BASH=Path('/bin/bash')
def generated_cases(home):
    """Byte expectations are composed before quoting; Bash is the decoder."""
    a=secrets.token_hex(12).encode();b=secrets.token_hex(12).encode()
    shapes=[
        ('bare',a,a),('single',b"'"+a+b"'",a),('double',b'"'+a+b'"',a),
        ('adjacent',b"'"+a[:12]+b"'\""+a[12:]+b'"',a),
        ('escaped_space',a+b'\\ '+b,a+b' '+b),
        ('hash_in_word',a+b'#'+b,a+b'#'+b),
        ('single_hash',b"'"+a+b'#'+b+b"'",a+b'#'+b),
        ('double_hash',b'"'+a+b'#'+b+b'"',a+b'#'+b),
        ('escaped_hash',a+b'\\#'+b,a+b'#'+b),
        ('escaped_backslash',a+b'\\\\'+b,a+b'\\'+b),
        ('double_backslash_q',b'"'+a+b'\\q"',a+b'\\q'),
        ('double_backslash_space',b'"'+a+b'\\ "',a+b'\\ '),
        ('double_escaped_quote',b'"'+a+b'\\"'+b+b'"',a+b'"'+b),
        ('single_backslash',b"'"+a+b'\\q'+b"'",a+b'\\q'),
        ('single_space',b"'"+a+b' '+b+b"'",a+b' '+b),
        ('assignment_glob',a+b'*?[]',a+b'*?[]'),
        ('assignment_braces',a+b'{x,y}',a+b'{x,y}'),
        ('equals',a+b'='+b,a+b'='+b),
        ('quoted_semicolon',b"'"+a+b';'+b+b"'",a+b';'+b),
        ('quoted_ampersand',b'"'+a+b'&'+b+b'"',a+b'&'+b),
        ('utf8',b"'"+a+chr(0x1f512).encode()+b"'",a+chr(0x1f512).encode()),
        ('quoted_tab',b"'"+a+b'\t'+b+b"'",a+b'\t'+b),
        ('quoted_cr',b"'"+a+b'\r'+b+b"'",a+b'\r'+b),
        ('empty_bare',b'',b''),('empty_single',b"''",b''),('empty_double',b'""',b''),
    ]
    cases=[]
    def add(name,source,expected_a,expected_b=None,policy='literal_candidate',rewrite=True,mutation=None):
        cases.append(dict(name=name,source=source,a=expected_a,b=expected_b,policy=policy,
                          proposed_whole_line_delete_eligible=rewrite,mutation=mutation))
    for exported in (False,True):
        prefix=b'\texport ' if exported else b''
        for name,encoded,value in shapes:
            expanded_braces=exported and name=='assignment_braces'
            add(('export_' if exported else 'assign_')+name,
                prefix+b'EC_ORACLE_A='+encoded+b'\n',a+b'y' if expanded_braces else value,
                policy='manual_expansion_proposed' if expanded_braces else 'literal_candidate',
                rewrite=not expanded_braces and name != 'quoted_cr')
    add('export_quoted_braces',b"export EC_ORACLE_A='"+a+b"{x,y}'\n",a+b'{x,y}')
    add('trailing_comment',b'EC_ORACLE_A='+a+b' # ignored\n',a)
    add('comment_dollar',b'EC_ORACLE_A='+a+b' # $OTHER ignored\n',a)
    add('comment_backtick',b'EC_ORACLE_A='+a+b' # `ignored`\n',a)
    add('comment_backslash',b'EC_ORACLE_A='+a+b' # ignored\\\n',a)
    add('crlf_assignment',b'EC_ORACLE_A='+a+b'\r\n',a+b'\r',rewrite=False)
    add('quoted_multiline',b"EC_ORACLE_A='"+a+b'\n'+b+b"'\n",a+b'\n'+b,rewrite=False)
    add('continuation',b'EC_ORACLE_A='+a+b'\\\n'+b+b'\n',a+b,rewrite=False)
    add('double_continuation',b'EC_ORACLE_A="'+a+b'\\\n'+b+b'"\n',a+b,rewrite=False)
    add('same_line_semicolon',b'EC_ORACLE_A='+a+b'; EC_ORACLE_B='+b+b'\n',a,b,policy='manual_context',rewrite=False)
    add('same_line_export',b'export EC_ORACLE_A='+a+b' EC_ORACLE_B='+b+b'\n',a,b,policy='manual_context',rewrite=False)
    add('same_line_and',b'EC_ORACLE_A='+a+b' && EC_ORACLE_B='+b+b'\n',a,b,policy='manual_context',rewrite=False)
    # Policy expectations are independent of actual Bash decoding. The plan
    # conservatively reports names only whenever the value syntax contains $/`.
    add('single_dollar',b"EC_ORACLE_A='$"+a+b"'\n",b'$'+a,policy='template_name_only',rewrite=False)
    add('escaped_dollar',b'EC_ORACLE_A=\\$'+a+b'\n',b'$'+a,policy='template_name_only',rewrite=False)
    add('single_backtick',b"EC_ORACLE_A='`"+a+b"`'\n",b'`'+a+b'`',policy='template_name_only',rewrite=False)
    add('parameter_expansion',b'EC_ORACLE_INPUT='+a+b'\nEC_ORACLE_A="$EC_ORACLE_INPUT"\n',a,policy='template_name_only',rewrite=False)
    add('command_substitution',b"EC_ORACLE_A=$(builtin printf '%s' '"+a+b"')\n",a,policy='manual_command_substitution',rewrite=False)
    add('backtick_substitution',b"EC_ORACLE_A=`builtin printf '%s' '"+a+b"'`\n",a,policy='manual_expansion_proposed',rewrite=False)
    add('arithmetic',b'EC_ORACLE_A=$((6*7))\n',str(6*7).encode(),policy='manual_expansion_proposed',rewrite=False)
    add('ansi_c_quote',b"EC_ORACLE_A=$'"+a+b"\\n'\n",a+b'\n',policy='template_name_only',rewrite=False)
    add('tilde_expansion',b'EC_ORACLE_A=~/fixture\n',str(home).encode()+b'/fixture',policy='manual_expansion_proposed',rewrite=False)
    add('quoted_tilde',b"EC_ORACLE_A='~/fixture'\n",b'~/fixture')
    # Two deletions produce syntactically valid but different shell behavior.
    add('deletion_continuation',b'EC_ORACLE_A='+a+b'\\\nEC_ORACLE_B='+b+b'\n',a+b'EC_ORACLE_B='+b,rewrite=False)
    add('deletion_quoted_multiline',b"EC_ORACLE_A='"+a+b'\n'+b+b"'\n",a+b'\n'+b,rewrite=False)
    return cases

# Data is returned through a dedicated inherited pipe, never stdout/stderr or
# argv. Every sourced byte was generated above in an owned private directory.
DRIVER=r'''
unset EC_ORACLE_A EC_ORACLE_B EC_ORACLE_INPUT
builtin source "$1" >/dev/null 2>/dev/null
ec_status=$?
builtin printf '%s\0' "$ec_status" "${EC_ORACLE_A+x}" "${EC_ORACLE_A-}" "${EC_ORACLE_B+x}" "${EC_ORACLE_B-}" "${EC_PARENT_ONLY+x}" >&"$2"
'''

def observe(source,root):
    fixture=root/'fixture.sh';fixture.write_bytes(source)
    rd,wr=os.pipe()
    proc=None
    try:
        proc=subprocess.Popen([str(BASH),'--noprofile','--norc','-c',DRIVER,'oracle',str(fixture),str(wr)],
            cwd=root,env={'HOME':str(root/'home'),'PATH':str(root/'empty-path'),'LC_ALL':'C'},
            pass_fds=(wr,),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        os.close(wr);wr=None
        out,err=proc.communicate(timeout=3)
        with os.fdopen(rd,'rb') as stream:data=stream.read(65536)
        rd=None
        fields=data.split(b'\0')
        valid=len(fields)==7 and fields[-1]==b''
        return {'exit':proc.returncode,'source_status':int(fields[0]) if valid and fields[0].isdigit() else None,
                'a':fields[2] if valid and fields[1]==b'x' else None,
                'b':fields[4] if valid and fields[3]==b'x' else None,
                'framing_valid':valid,'inherited_marker_absent':valid and fields[5]==b'',
                'stdout_bytes':len(out),'stderr_bytes':len(err)}
    finally:
        if proc is not None and proc.poll() is None:proc.kill();proc.wait(timeout=3)
        if wr is not None:os.close(wr)
        if rd is not None:os.close(rd)


root=Path(sys.argv[1]); (root/'home').mkdir(); (root/'empty-path').mkdir()
rows=[]
for case in generated_cases(root/'home'):
    observed=observe(case['source'],root)
    assert observed['framing_valid'] and observed['inherited_marker_absent']
    assert observed['exit']==0 and observed['stdout_bytes']==observed['stderr_bytes']==0
    assert observed['a']==case['a'] and observed['b']==case['b']
    name=case['name']+'.sh'; (root/name).write_bytes(case['source'])
    value=observed['a']
    rows.append(dict(name=case['name'],source_file=name,expected_a={'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()},proposed_policy=case['policy'],proposed_whole_line_delete_eligible=case['proposed_whole_line_delete_eligible']))
print(json.dumps(rows))
