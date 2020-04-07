import React from 'react'
import styles from './Resume.module.css'
import {ThemeContext} from "../../Theme";
import classNames from 'classnames/bind';

let cx = classNames.bind(styles);

class Resume extends React.Component {
    static contextType = ThemeContext

    render() {
        return (
            <a href={process.env.PUBLIC_URL + '/resume.pdf'}>
                <div className={cx('landingResumeButton', this.context)}>Resume</div>
            </a>
        );
    }
}

export default Resume;