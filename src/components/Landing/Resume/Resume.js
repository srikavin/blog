import React from 'react'
import './Resume.css'

class Resume extends React.Component {
    fetchResume() {
        return () => {
            window.open(process.env.PUBLIC_URL + '/resume.pdf', '_blank')
        }
    }

    render() {
        return (
            <div className={'landingResumeButton'}
                 onClick={this.fetchResume()}>Download Resume</div>
        );
    }
}

export default Resume;