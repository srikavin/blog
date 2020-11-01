import React from 'react';
import styles from './PostTags.module.css'
import Skeleton from '../../../util/Skeleton/Skeleton';
import Tag from '../../../util/Tag/Tag';
import {Link} from "react-router-dom";

class PostTags extends React.Component {
    genTagsBlock() {
        if (!this.props.tags) {
            return <Skeleton align={'center'} className={styles.skeleton}/>;
        }

        return this.props.tags.map(e => (
            <Link key={e.id} to={`/tag/${e.id}`}>
                <Tag interactive={true} className={styles.item} minimal={true}>{e.name}</Tag>
            </Link>
        ));
    }

    render() {
        return (
            <div className={this.props.className}>
                {this.genTagsBlock()}
            </div>
        );
    }
}

export default PostTags;
